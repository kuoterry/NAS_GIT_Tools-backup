# -*- coding: utf-8 -*-
"""nas_git_connector 純函數迴歸測試（stdlib unittest，零額外依賴）。

執行：py -m unittest discover -s tests -v （或 python -m unittest ...）
只測不碰網路/NAS/GUI 的純函數；事故史證明這類解析/白名單函數的邊界
案例都是真實資料才炸出來的，炸過一次就該固化在這裡。
"""
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nas_git_connector as ngc


class TestIsSafeName(unittest.TestCase):
    def test_accepts_normal_names(self):
        for name in ("MyRepo", "my-repo.git", "a1", "專案倉庫", "repo_v2", "R.2"):
            self.assertTrue(ngc.is_safe_name(name), name)

    def test_rejects_reserved_and_traversal(self):
        for name in (".", "..", "_archived", "", "_leading", ".hidden",
                     "-dash", "a/b", "a b", "a;b", "a`b", "a$b", "a'b"):
            self.assertFalse(ngc.is_safe_name(name), name)


class TestShq(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(ngc.shq("abc"), "'abc'")

    def test_embedded_single_quote(self):
        # 'a'\''b'：單引號內先關引號、跳脫一個引號、再開引號
        self.assertEqual(ngc.shq("a'b"), "'a'\\''b'")

    def test_shell_metachars_stay_literal(self):
        quoted = ngc.shq("$(rm -rf /)`x`")
        self.assertTrue(quoted.startswith("'") and quoted.endswith("'"))
        self.assertNotIn('"', quoted)


class TestBetween(unittest.TestCase):
    def test_strips_banner(self):
        out = "Welcome to DSM!\n___BEGIN___\nreal\ncontent\n___END___\ntrailing"
        self.assertEqual(ngc.Worker._between(out), "real\ncontent")

    def test_missing_markers_returns_all(self):
        self.assertEqual(ngc.Worker._between("no markers here"), "no markers here")

    def test_empty_body(self):
        self.assertEqual(ngc.Worker._between("___BEGIN___\n___END___"), "")


class TestEffectiveRepoKind(unittest.TestCase):
    def test_mirror_flag_overrides_kind(self):
        # mirror 是權威：nasgit.kind 說什麼都不算（CLAUDE.md 明定的不變量）
        self.assertEqual(ngc.effective_repo_kind("true", "own"), "mirror")

    def test_kind_passthrough(self):
        self.assertEqual(ngc.effective_repo_kind("", "fork"), "fork")

    def test_unclassified(self):
        self.assertEqual(ngc.effective_repo_kind("", ""), "")


class TestSshFingerprint(unittest.TestCase):
    def test_garbage_line(self):
        self.assertEqual(ngc.ssh_fingerprint("not a key"), "?")
        self.assertEqual(ngc.ssh_fingerprint(""), "?")
        self.assertEqual(ngc.ssh_fingerprint("ssh-ed25519 %%%bad-base64%%% c"), "?")

    @unittest.skipUnless(shutil.which("ssh-keygen"), "需要 ssh-keygen")
    def test_matches_ssh_keygen(self):
        # 拿 ssh-keygen -lf 當權威對照，不是拿實作對照實作
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "k")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key],
                           capture_output=True, input="", text=True, timeout=30, check=True)
            with open(key + ".pub", encoding="utf-8") as f:
                pub_line = f.read().strip()
            lf = subprocess.run(["ssh-keygen", "-lf", key + ".pub"],
                                capture_output=True, text=True, timeout=30, check=True)
            expected = next(t for t in lf.stdout.split() if t.startswith("SHA256:"))
            self.assertEqual(ngc.ssh_fingerprint(pub_line), expected)


class TestMergeProfiles(unittest.TestCase):
    def _p(self, user, updated_at, machines):
        return {"user": user, "host": "h", "remote_root": "/volume1/Git_Server",
                "identity_file": "", "updated_at": updated_at, "machines": machines}

    def test_newer_updated_at_wins(self):
        local = {"家中": self._p("old", "2026-01-01T00:00:00Z", ["PC1"])}
        remote = {"家中": self._p("new", "2026-06-01T00:00:00Z", ["PC2"])}
        merged, added, updated = ngc.MainWindow._merge_profiles(local, remote)
        self.assertEqual(merged["家中"]["user"], "new")

    def test_machines_always_union(self):
        # machines 聯集、只加不減：一台機器同步不能洗掉另一台的綁定
        local = {"家中": self._p("a", "2026-06-01T00:00:00Z", ["PC1"])}
        remote = {"家中": self._p("b", "2026-01-01T00:00:00Z", ["PC2"])}
        merged, _, _ = ngc.MainWindow._merge_profiles(local, remote)
        self.assertEqual(merged["家中"]["machines"], ["PC1", "PC2"])
        self.assertEqual(merged["家中"]["user"], "a")  # 本地較新，user 留本地值

    def test_identity_file_never_taken_from_remote(self):
        # identity_file 是機器本地路徑，遠端較新也不能帶過來
        local = {"家中": self._p("a", "2026-01-01T00:00:00Z", [])}
        local["家中"]["identity_file"] = r"C:\keys\id_ed25519"
        remote = {"家中": self._p("b", "2026-06-01T00:00:00Z", [])}
        remote["家中"]["identity_file"] = "/home/other/.ssh/id"
        merged, _, _ = ngc.MainWindow._merge_profiles(local, remote)
        self.assertEqual(merged["家中"]["identity_file"], r"C:\keys\id_ed25519")

    def test_remote_only_profile_added(self):
        merged, added, _ = ngc.MainWindow._merge_profiles(
            {}, {"公司": self._p("x", "2026-01-01T00:00:00Z", ["PC9"])})
        self.assertEqual(added, 1)
        self.assertIn("公司", merged)


class TestAuditKeyScript(unittest.TestCase):
    """補金鑰/輪替腳本的稽核落地。

    這條路徑的洞是真的被踩到的：2026-08-14 在 git_user2 的 authorized_keys 上
    翻出兩把查無來源的金鑰，因為當時這兩個對話框只產生腳本、什麼都沒記。
    """

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        self._orig = ngc.AUDIT_LOG_PATH
        ngc.AUDIT_LOG_PATH = os.path.join(self._dir, "audit.log")

    def tearDown(self):
        ngc.AUDIT_LOG_PATH = self._orig
        shutil.rmtree(self._dir, ignore_errors=True)

    def _line(self):
        with open(ngc.AUDIT_LOG_PATH, encoding="utf-8") as f:
            return f.read().strip()

    # 合成金鑰（ed25519 wire format，內容是 0x00..0x1f），不是任何真實帳號的金鑰
    PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
           " git_user2")

    def test_records_fingerprint_not_the_key_body(self):
        # 指紋才是事後跟 Key_Management 名冊／NAS 比對報表對得起來的欄位；
        # 公鑰本體不該進稽核（比對用不到，只是把檔案撐大）
        ok = ngc.audit_key_script({"user": "kuoterry", "host": "nas"},
                                  "gen_addkey_script", "git_user2", [("新增", self.PUB)])
        self.assertTrue(ok)
        line = self._line()
        self.assertIn(ngc.ssh_fingerprint(self.PUB), line)
        self.assertNotIn("AAAAIAABAgMEBQYHCAkKCwwNDg8Q", line)
        self.assertIn("帳號=git_user2", line)
        self.assertIn("gen_addkey_script", line)

    def test_never_claims_the_script_was_run(self):
        # 這裡不可能知道使用者有沒有真的去貼那段腳本，寫成既成事實＝稽核說謊
        ngc.audit_key_script({"user": "u", "host": "h"}, "gen_addkey_script",
                             "git_user2", [("新增", self.PUB)])
        self.assertIn("未知", self._line())

    def test_rotation_records_both_directions(self):
        old = self.PUB
        new = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7l1n8s5b1BsD0hZzYq0dQ2M4vXk9CkGZ3rTfWpQqLm rotated"
        ngc.audit_key_script({"user": "u", "host": "h"}, "gen_rotatekey_script",
                             "git_user2", [("新增", new), ("撤銷", old)])
        line = self._line()
        self.assertIn("新增=" + ngc.ssh_fingerprint(new), line)
        self.assertIn("撤銷=" + ngc.ssh_fingerprint(old), line)

    def test_notes_only_call_has_no_key_fields(self):
        # 移除帳號沒有金鑰可記，但「同時刪除 DSM 帳號」不可逆，非留紀錄不可
        ngc.audit_key_script({"user": "u", "host": "h"}, "gen_removeuser_script", "git_user9",
                             notes=[("同時刪除DSM帳號", "是"), ("移除後成員", "kuoterry Git_User1")])
        line = self._line()
        self.assertIn("同時刪除DSM帳號=是", line)
        self.assertIn("移除後成員=kuoterry Git_User1", line)
        self.assertNotIn("SHA256:", line)
        self.assertIn("未知", line)

    def test_single_line_per_call(self):
        # audit_sync 靠 sort -u 合併多機紀錄，一筆換行就會把時間軸切爛
        ngc.audit_key_script({"user": "u", "host": "h"}, "gen_addkey_script",
                             "git_user2", [("新增", self.PUB)])
        with open(ngc.AUDIT_LOG_PATH, encoding="utf-8") as f:
            self.assertEqual(len(f.readlines()), 1)


class TestVersionResource(unittest.TestCase):
    """exe 的 Windows 版本資源必須跟 __version__ 對得起來。

    在這之前版本只存在於檔名（build_exe.bat 的 copy 產生），exe 內部查不到任何
    版號可以佐證——檔名一旦錯了沒人看得出來。這幾個測試盯的就是那條產生路徑。
    """

    def setUp(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, root)
        import get_version
        self.gv = get_version
        self.root = root

    def test_read_version_matches_module(self):
        # get_version.py 用 regex 讀原始碼，import 的是真的執行結果，兩邊必須一致
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            self.assertEqual(self.gv.read_version(), ngc.__version__)
        finally:
            os.chdir(cwd)

    def test_version_tuple_always_four_ints(self):
        self.assertEqual(self.gv.version_tuple("2.12.3"), (2, 12, 3, 0))
        self.assertEqual(self.gv.version_tuple("1.9"), (1, 9, 0, 0))
        self.assertEqual(self.gv.version_tuple("2.0.0rc1"), (2, 0, 0, 0))

    def test_rendered_file_is_valid_python_and_carries_the_version(self):
        # PyInstaller 是直接 eval 這個檔案的，語法錯了會在建置最後一刻才炸
        text = self.gv.render_version_file("2.12.3")
        compile(text, "version_info.txt", "exec")   # 語法錯的話這裡就會丟 SyntaxError
        self.assertIn("filevers=(2, 12, 3, 0)", text)
        self.assertIn("StringStruct('FileVersion', '2.12.3')", text)
        self.assertIn("StringStruct('ProductVersion', '2.12.3')", text)


if __name__ == "__main__":
    unittest.main()

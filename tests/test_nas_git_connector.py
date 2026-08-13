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


if __name__ == "__main__":
    unittest.main()

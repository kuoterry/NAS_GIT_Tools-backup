# -*- coding: utf-8 -*-
"""key_management 純函數迴歸測試（stdlib unittest，零額外依賴）。

執行：cd Key_Management && py -m unittest discover -s tests -v
事故史（RFC4716 沒解析、known_hosts 多演算法誤判、壞 ppk 炸全掃描…）全是真實
資料才炸出來的——每修一個解析邊界就在這裡釘一根迴歸釘。"""
import base64
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import key_management as km

# 一把合法的 ed25519 公鑰（測試專用、無對應私鑰流通，僅供解析器測試）
ED25519_PUB = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6/CMcgpNVUEUsRxvpqrdWyAP4RmNyMzYYnPvA1Pfe4"
               " test@example")


class TestParsePubkeyLine(unittest.TestCase):
    def test_valid_line(self):
        parsed = km.parse_pubkey_line(ED25519_PUB)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "ssh-ed25519")
        self.assertEqual(parsed["comment"], "test@example")

    def test_garbage(self):
        self.assertIsNone(km.parse_pubkey_line("this is not a key"))
        self.assertIsNone(km.parse_pubkey_line(""))


class TestParseRfc4716(unittest.TestCase):
    def test_putty_export_format(self):
        # PuTTYgen「export OpenSSH key」有些版本吐這種多行 SSH2 格式（真實踩雷案例）
        b64 = ED25519_PUB.split()[1]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "putty_style.pub")
            with open(p, "w", encoding="utf-8") as f:
                f.write("---- BEGIN SSH2 PUBLIC KEY ----\n"
                        'Comment: "putty-comment"\n'
                        + "\n".join(b64[i:i + 60] for i in range(0, len(b64), 60)) + "\n"
                        "---- END SSH2 PUBLIC KEY ----\n")
            parsed = km.parse_pubkey_file(p)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "ssh-ed25519")
        self.assertEqual(parsed["comment"], "putty-comment")


class TestParsePpkPubkey(unittest.TestCase):
    def test_public_lines_block(self):
        b64 = ED25519_PUB.split()[1]
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k.ppk")
            with open(p, "w", encoding="utf-8") as f:
                f.write("PuTTY-User-Key-File-3: ssh-ed25519\n"
                        "Encryption: none\n"
                        "Comment: ppk-comment\n"
                        f"Public-Lines: {len(lines)}\n"
                        + "\n".join(lines) + "\n"
                        "Private-Lines: 1\n"
                        "FAKEFAKEFAKE\n")
            parsed = km.parse_ppk_pubkey(p)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "ssh-ed25519")

    def test_malformed_ppk_returns_none(self):
        # 壞 ppk 要回 None，不能讓例外炸掉整個掃描（2026-08 修過的雷）
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.ppk")
            with open(p, "w", encoding="utf-8") as f:
                f.write("PuTTY-User-Key-File-3: ssh-ed25519\nPublic-Lines: 99\n")
            self.assertIsNone(km.parse_ppk_pubkey(p))


class TestClassifyPrivateKeyFile(unittest.TestCase):
    def test_ppk_encrypted_flag(self):
        with tempfile.TemporaryDirectory() as d:
            enc = os.path.join(d, "enc.ppk")
            with open(enc, "w", encoding="utf-8") as f:
                f.write("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n")
            plain = os.path.join(d, "plain.ppk")
            with open(plain, "w", encoding="utf-8") as f:
                f.write("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n")
            self.assertEqual(km.classify_private_key_file(enc),
                             {"format": "ppk", "encrypted": True})
            self.assertEqual(km.classify_private_key_file(plain),
                             {"format": "ppk", "encrypted": False})

    def test_pem_rsa_proc_type(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k")
            with open(p, "w", encoding="utf-8") as f:
                f.write("-----BEGIN RSA PRIVATE KEY-----\n"
                        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCD\n\nxxxx\n"
                        "-----END RSA PRIVATE KEY-----\n")
            cls = km.classify_private_key_file(p)
        self.assertEqual(cls["format"], "pem-rsa")
        self.assertTrue(cls["encrypted"])

    @unittest.skipUnless(shutil.which("ssh-keygen"), "需要 ssh-keygen")
    def test_real_openssh_keys(self):
        with tempfile.TemporaryDirectory() as d:
            plain = os.path.join(d, "plain")
            enc = os.path.join(d, "enc")
            for path, pw in ((plain, ""), (enc, "s3cret-pass")):
                subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", pw, "-f", path],
                               capture_output=True, input="", text=True, timeout=30, check=True)
            self.assertEqual(km.classify_private_key_file(plain),
                             {"format": "openssh", "encrypted": False})
            self.assertEqual(km.classify_private_key_file(enc),
                             {"format": "openssh", "encrypted": True})


class TestBuildAdvisories(unittest.TestCase):
    def _base_rec(self):
        return {"priv_path": "/x/k", "pub_path": "/x/k.pub", "type": "ssh-ed25519",
                "strength": "Ed25519", "fingerprint": "SHA256:x", "mtime": time.time()}

    def test_unencrypted_openssh_mentions_button(self):
        rec = dict(self._base_rec(), priv_encrypted=False, priv_format="openssh")
        notes = km.build_advisories(rec, {})
        self.assertIn("私鑰未加密", notes)
        self.assertIn("加上密碼保護", notes)

    def test_unencrypted_ppk_mentions_puttygen(self):
        rec = dict(self._base_rec(), priv_encrypted=False, priv_format="ppk")
        notes = km.build_advisories(rec, {})
        self.assertIn("私鑰未加密", notes)
        self.assertIn("PuTTYgen", notes)

    def test_encrypted_key_no_warning(self):
        rec = dict(self._base_rec(), priv_encrypted=True, priv_format="openssh")
        self.assertNotIn("私鑰未加密", km.build_advisories(rec, {}))

    def test_age_threshold_is_configurable(self):
        rec = dict(self._base_rec(), priv_encrypted=True, priv_format="openssh",
                   mtime=time.time() - 400 * 86400)
        self.assertIn("可考慮輪替", km.build_advisories(rec, {}, age_days=365))
        self.assertNotIn("可考慮輪替", km.build_advisories(rec, {}, age_days=730))


class TestRewriteSshConfigIdentity(unittest.TestCase):
    def test_rewrites_only_matching_lines(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config")
            old = os.path.join(d, "id_old")
            other = os.path.join(d, "id_other")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write("Host nas\n"
                        f'    IdentityFile "{old}"\n'
                        "Host github\n"
                        f"    IdentityFile {other}\n")
            changed, msg = km.rewrite_ssh_config_identity(old, os.path.join(d, "id_new"),
                                                          config_path=cfg)
            self.assertEqual(changed, 1)
            with open(cfg, encoding="utf-8") as f:
                text = f.read()
            self.assertIn("id_new", text)
            self.assertIn(f"IdentityFile {other}", text)  # 別人的行原封不動
            # 改寫前要留備份
            self.assertTrue(any(fn.startswith("config.bak-") for fn in os.listdir(d)))

    def test_no_match_no_touch(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write("Host nas\n    IdentityFile ~/.ssh/id_x\n")
            changed, _ = km.rewrite_ssh_config_identity(os.path.join(d, "nope"),
                                                        os.path.join(d, "new"), config_path=cfg)
            self.assertEqual(changed, 0)
            self.assertFalse(any(fn.startswith("config.bak-") for fn in os.listdir(d)))


class TestAuditPlumbing(unittest.TestCase):
    """1.4.0～1.5.0 的真實事故：audit_log 沒 return、audit_failed_note 沒定義，
    動作做完卻在成功路徑炸 NameError 被吞成「發生未預期錯誤」。
    這裡直接打 Worker 的成功路徑，純函數測試蓋不到這種洞。"""

    def test_audit_log_returns_bool(self):
        orig_app, orig_log = km.APP_DIR, km.AUDIT_LOG_PATH
        try:
            with tempfile.TemporaryDirectory() as d:
                km.APP_DIR = d
                km.AUDIT_LOG_PATH = os.path.join(d, "audit.log")
                self.assertIs(km.audit_log("test", "detail"), True)
        finally:
            km.APP_DIR, km.AUDIT_LOG_PATH = orig_app, orig_log

    def test_audit_failed_note_both_branches(self):
        self.assertEqual(km.audit_failed_note(True), "")
        self.assertIn("稽核紀錄寫入失敗", km.audit_failed_note(False))

    def test_worker_archive_delete_success_path(self):
        orig = (km.APP_DIR, km.AUDIT_LOG_PATH, km.ARCHIVE_DIR)
        try:
            with tempfile.TemporaryDirectory() as d:
                km.APP_DIR = d
                km.AUDIT_LOG_PATH = os.path.join(d, "audit.log")
                km.ARCHIVE_DIR = os.path.join(d, "archive")
                priv = os.path.join(d, "id_test")
                pub = priv + ".pub"
                for p in (priv, pub):
                    with open(p, "w", encoding="utf-8") as f:
                        f.write("dummy\n")
                results = []
                w = km.Worker("delete", {"pub_path": pub, "priv_path": priv, "hard": False})
                w.done.connect(lambda ok, msg: results.append((ok, msg)))
                w._run_delete()
                self.assertTrue(results, "done 沒發射")
                ok, msg = results[0]
                self.assertTrue(ok, f"封存成功路徑回報失敗：{msg}")
                self.assertFalse(os.path.exists(priv))
        finally:
            km.APP_DIR, km.AUDIT_LOG_PATH, km.ARCHIVE_DIR = orig


class TestIcaclsParsing(unittest.TestCase):
    SAMPLE = (
        "C:\\Users\\me\\.ssh\\id_test NT AUTHORITY\\SYSTEM:(F)\n"
        "               BUILTIN\\Administrators:(F)\n"
        "               BUILTIN\\Users:(RX)\n"
        "               Everyone:(R)\n"
        "               PC\\Git_User1:(F)\n"
    )

    def test_flags_broad_groups_only(self):
        hits = km.parse_icacls_broad_principals(self.SAMPLE)
        joined = " ".join(hits)
        self.assertIn("Users", joined)
        self.assertIn("Everyone", joined)
        # 帳號名剛好含 user 子字串（Git_User1）不能誤中——token 帶反斜線+冒號界定
        self.assertNotIn("Git_User1", joined)
        self.assertNotIn("SYSTEM", joined)

    def test_clean_acl_no_hits(self):
        clean = ("C:\\k NT AUTHORITY\\SYSTEM:(F)\n"
                 "     BUILTIN\\Administrators:(F)\n"
                 "     PC\\terry:(F)\n")
        self.assertEqual(km.parse_icacls_broad_principals(clean), [])

    def test_first_line_filename_prefix(self):
        # icacls 首行是「檔名 主體:(旗標)」黏在一起、沒有反斜線分隔——不能漏抓
        sample = "C:\\keys\\id_x Everyone:(R)\n     PC\\terry:(F)\n"
        hits = km.parse_icacls_broad_principals(sample)
        self.assertEqual(len(hits), 1)
        self.assertIn("Everyone", hits[0])


class TestPairMismatch(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ssh-keygen"), "需要 ssh-keygen")
    def test_stale_pub_flagged(self):
        # 兩把真鑰，把 B 的 .pub 蓋到 A 的 basename 上 → 配對驗證要抓到
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "id_a")
            b = os.path.join(d, "id_b")
            for p in (a, b):
                subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", p],
                               capture_output=True, input="", text=True, timeout=30, check=True)
            shutil.copy2(b + ".pub", a + ".pub")   # A 的 .pub 現在是 B 的（stale/換過）
            os.remove(b)
            os.remove(b + ".pub")
            records = km.build_records([d])
            # build_records 會把掃描根目錄 normcase（Windows 全小寫），路徑比對要跟進
            rec = next(r for r in records
                       if os.path.normcase(r.get("priv_path") or "") == os.path.normcase(a))
            self.assertTrue(rec.get("pair_mismatch"), "stale .pub 沒被抓到")
            self.assertIn(".pub 與私鑰不是同一把", rec.get("advisories", ""))

    @unittest.skipUnless(shutil.which("ssh-keygen"), "需要 ssh-keygen")
    def test_matching_pair_clean(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "id_ok")
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", a],
                           capture_output=True, input="", text=True, timeout=30, check=True)
            records = km.build_records([d])
            rec = next(r for r in records
                       if os.path.normcase(r.get("priv_path") or "") == os.path.normcase(a))
            self.assertFalse(rec.get("pair_mismatch"))


class TestHostLabels(unittest.TestCase):
    def test_label_host_translates(self):
        labels = {"terry_asus": "家中", "desktop-7f3k2m9": "公司"}
        self.assertEqual(km.label_host("Terry_ASUS", labels), "Terry_ASUS（家中）")
        self.assertEqual(km.label_host("DESKTOP-7F3K2M9", labels), "DESKTOP-7F3K2M9（公司）")

    def test_unknown_host_passthrough(self):
        self.assertEqual(km.label_host("UNKNOWN-PC", {"terry_asus": "家中"}), "UNKNOWN-PC")
        self.assertEqual(km.label_host("PC", {}), "PC")
        self.assertEqual(km.label_host("PC", None), "PC")

    def test_advisory_uses_labels(self):
        rec = {"priv_path": "/x/k", "pub_path": "/x/k.pub", "type": "ssh-ed25519",
               "strength": "Ed25519", "fingerprint": "SHA256:x",
               "mtime": time.time(), "priv_encrypted": True, "priv_format": "openssh"}
        seen = {"SHA256:x": {"PC1": "t", "PC2": "t"}}
        notes = km.build_advisories(rec, {}, seen, "PC1",
                                    host_labels={"pc2": "公司"})
        self.assertIn("PC2（公司）", notes)


class TestMergeRegistries(unittest.TestCase):
    def _entry(self, last_seen, comment, **kw):
        e = {"fingerprint": "SHA256:x", "last_seen": last_seen, "comment": comment,
             "pub_path": "/local/k.pub", "priv_path": "/local/k", "priv_format": "openssh",
             "priv_encrypted": True, "status": "active", "history": [], "seen_hosts": {}}
        e.update(kw)
        return e

    def test_machine_local_fields_never_overwritten(self):
        local = {"SHA256:x": self._entry("2026-01-01T00:00:00", "old-comment")}
        remote = {"SHA256:x": self._entry("2026-06-01T00:00:00", "new-comment",
                                          pub_path="/other/k.pub", status="missing")}
        merged = km.merge_registries(local, remote, "PC1")
        ent = merged["SHA256:x"]
        self.assertEqual(ent["comment"], "new-comment")      # 一般欄位：較新的贏
        self.assertEqual(ent["pub_path"], "/local/k.pub")    # 機器本地欄位：永遠留本機
        self.assertEqual(ent["status"], "active")

    def test_seen_hosts_union(self):
        local = {"SHA256:x": self._entry("2026-01-01T00:00:00", "c", seen_hosts={"PC1": "t1"})}
        remote = {"SHA256:x": self._entry("2026-02-01T00:00:00", "c", seen_hosts={"PC2": "t2"})}
        merged = km.merge_registries(local, remote, "PC1")
        self.assertEqual(set(merged["SHA256:x"]["seen_hosts"]), {"PC1", "PC2"})


class TestPrivateKeyPermissionsNeverCrashesScan(unittest.TestCase):
    """icacls 是唯一輸出系統語系編碼（繁中 Windows 是 cp950）的 subprocess。

    以前沒指定 encoding，直譯器跑在 UTF-8 模式時（PYTHONUTF8=1）解碼會丟
    UnicodeDecodeError——而那個例外不在函式的 except 清單裡，會炸穿整趟掃描，
    不是只讓權限檢查回空字串。這個測試在兩種模式下都要過。
    """

    def test_returns_string_and_does_not_raise(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k")
            with open(p, "w", encoding="utf-8") as f:
                f.write("dummy")
            self.assertIsInstance(km.check_private_key_permissions(p), str)

    def test_missing_file_is_not_an_error(self):
        self.assertIsInstance(
            km.check_private_key_permissions(os.path.join(tempfile.gettempdir(), "no-such-key-xyz")),
            str)

class TestVersionResource(unittest.TestCase):
    """exe 的 Windows 版本資源必須跟 __version__ 對得起來（見姊妹專案的同名測試）。"""

    def setUp(self):
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, self.root)
        import get_version
        self.gv = get_version

    def test_read_version_matches_module(self):
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            self.assertEqual(self.gv.read_version(), km.__version__)
        finally:
            os.chdir(cwd)

    def test_rendered_file_is_valid_python_and_carries_the_version(self):
        text = self.gv.render_version_file("1.9.1")
        compile(text, "version_info.txt", "exec")
        self.assertIn("filevers=(1, 9, 1, 0)", text)
        self.assertIn("StringStruct('FileVersion', '1.9.1')", text)
        self.assertIn("StringStruct('InternalName', 'KeyManagement')", text)


class TestCliHelpers(unittest.TestCase):
    """CLI 模式的格式化/過濾純函式。"""

    def test_record_to_dict_drops_blob_and_formats_mtime(self):
        rec = {"comment": "c", "blob": b"\x00\x01", "mtime": 1700000000.0, "fingerprint": "SHA256:x"}
        d = km.cli_record_to_dict(rec)
        self.assertNotIn("blob", d)                      # bytes 不可進 JSON
        self.assertEqual(d["comment"], "c")
        self.assertRegex(d["mtime"], r"^\d{4}-\d{2}-\d{2} ")
        self.assertIn("blob", rec)                       # 原 rec 不被改動

    def test_filter_advisory_records(self):
        recs = [{"advisories": "—"}, {"advisories": ""}, {"advisories": None},
                {"advisories": "⚠ 有事"}, {}]
        flagged = km.cli_filter_advisory_records(recs)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["advisories"], "⚠ 有事")

    def test_registry_table_active_first_and_empty(self):
        self.assertEqual(km.cli_format_registry_table({}), "（名冊是空的）")
        reg = {"a": {"status": "missing", "comment": "aaa", "fingerprint": "f1"},
               "b": {"status": "active", "comment": "bbb", "fingerprint": "f2"}}
        lines = km.cli_format_registry_table(reg).splitlines()
        self.assertTrue(lines[0].startswith("active"))
        self.assertTrue(lines[1].startswith("missing"))

    def test_records_table_empty_and_encrypted_marker(self):
        self.assertEqual(km.cli_format_records_table([]), "（沒有金鑰）")
        rec = {"priv_path": r"C:\k\id_ed25519", "type": "ssh-ed25519", "strength": "極佳",
               "fingerprint": "SHA256:y", "comment": "me", "priv_format": "openssh-v1",
               "priv_encrypted": True, "advisories": "—"}
        line = km.cli_format_records_table([rec])
        self.assertIn("id_ed25519", line)
        self.assertIn("+加密", line)


if __name__ == "__main__":
    unittest.main()

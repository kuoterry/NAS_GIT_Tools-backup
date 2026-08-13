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


if __name__ == "__main__":
    unittest.main()

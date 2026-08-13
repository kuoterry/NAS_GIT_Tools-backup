# OPS_LOG.md

NAS 端手動維運操作紀錄——記錄**不經 GUI 工具**、因此不會出現在本機稽核紀錄（`~/.nas_git_connector/audit.log`）裡的管理動作。GUI 內做的操作不用記在這裡，稽核紀錄已涵蓋。

事故與 post-mortem 請寫 [`INCIDENTS.md`](INCIDENTS.md)，這裡只記正常維運。

由新到舊。

---

## 2026-08-13 — 撤銷 kuoterry authorized_keys 中 Git_User1 的金鑰（身份交叉）

- **動作**：從 NAS `kuoterry` 的 `~/.ssh/authorized_keys` 移除指紋 `SHA256:CqIY44pKGw9E0adNCPyR8iN07WGOw3fCMOOuoeVsWjE`（註解 `Git_User1@kcc3713.synology.me`，RSA 4096）。手動 SSH 執行，比照工具慣例先備份：`authorized_keys.bak-20260813-204154`。
- **原因**：這是 Git_User1（公司身份）自己的金鑰，卻被授權登入 kuoterry（管理員帳號）——持有 Git_User1 私鑰即可直通 kuoterry，屬身份交叉，決定撤銷。來源不明（Key_Management 名冊與跨機器同步檔均無紀錄），推測為早期佈建時誤加。
- **驗證**：撤銷後 authorized_keys 剩 5 行（6→5），家機兩把常用金鑰（`bJM6…` id_ed25519、`Ejun…` id_rsa）確認仍在，連線正常；Key_Management 重跑比對結果一致。
- **待辦**：另外三把「只在 NAS」的 ❓ 金鑰（`5yCe…` sshfs-nas、`Znict…` rsa-key-20251211、`MtN55…` kuoterry-git）研判是公司機的金鑰，**先不撤**——等公司機跑過 Key_Management 掃描＋跨機器同步後重比對，屆時仍無主的才撤銷。

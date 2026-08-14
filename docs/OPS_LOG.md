# OPS_LOG.md

NAS 端手動維運操作紀錄——記錄**不經 GUI 工具**、因此不會出現在本機稽核紀錄（`~/.nas_git_connector/audit.log`）裡的管理動作。GUI 內做的操作不用記在這裡，稽核紀錄已涵蓋。

事故與 post-mortem 請寫 [`INCIDENTS.md`](INCIDENTS.md)，這裡只記正常維運。

由新到舊。

---

## 2026-08-14 — 手動把家機名冊從 .bak 合併回 NAS，並放寬 km_registry_sync.json 權限

跨機器金鑰名冊同步一直是壞的（兩台用不同身份、檔案 600、互相蓋掉，完整經過見 [`INCIDENTS.md`](INCIDENTS.md) 2026-08-14）。程式已修（Key_Management 1.9.0），但 NAS 上當下那份已經只剩公司機的資料，需要手動補救。

- **動作**：取 `/volume1/Git_Server/config/km_registry_sync.json.bak-20260813-201251`（家機 `Terry_ASUS` 8 筆）與公司機本機名冊 6 筆，用 `merge_registries()` 合併成 14 筆（指紋無重疊），寫回本機 `registry.json`（先備份 `registry.json.bak-20260814-110345`），再以 `git_user2` 身份推回 NAS，推之前照慣例 `cp` 一份 `.bak-<時間戳>`。
- **權限**：`chmod 660` ＋ `chgrp git_devs`，結果 `-rw-rw---- 1 git_user2 git_devs`。
- **驗證**：以 `kuoterry` 身份（另一個身份）實際讀取該檔成功，`entries: 14`、`seen_hosts: {'Terry_ASUS': 8, 'ACER_NB': 6}`。修好前這一步是 Permission denied。
- **附帶**：把 `Terry_ASUS` 綁到 NasGitConnector 的「家中 (kuoterry)」身份（原本 `machines` 是空的，所以標籤只會顯示 hostname）。綁定清單在 profile 同步時是聯集，不會踢掉別台。公司機這台目前綁在名為 `Git_User1` 的身份上，所以標籤顯示「ACER_NB（Git_User1）」——要顯示成「公司」得自己把該身份改名，工具不會猜。

## 2026-08-14 — `git_user2` 兩把 ❓ 解掉一把

承上，名冊合併後重新比對：

- **`SHA256:UGd6fB9FZDqric/U6h2FjjdiHmVjoNXIdEFX3iz9NFE`（註解 `git_user2`）確認是家機 `Terry_ASUS` 的金鑰，不可撤。**
- **`SHA256:jpGFBvLBqUzKd3d4IZ5S+iLXFsdPho+mF/NMMBcsXEY` 仍無主**——家機名冊裡三把 `git_user2` 註解的金鑰（`1h0dbSPZ…`／`PQw3Nfb…`／`UGd6fB9…`）都不是它。
- kuoterry 的 `bJM6…`(sshfs-nas)、`Ejun…` 確認是家機的。**`5yCe…`(sshfs-nas)、`Znict…`(rsa-key-20251211) 仍無主**——注意家機有一把 `zM/FH+H+…` 註解同樣是 `rsa-key-20251211`，但**指紋不同、是另一把**，不能拿註解當歸屬證據。
- 三把無主金鑰（`jpGF…`、`5yCe…`、`Znict…`）維持不撤。兩台機器現在都在名冊裡了，下一步要確認的是「有沒有第三個來源」（手機、路由器 sshfs、舊機器），確認沒有才撤。

## 2026-08-14 — 公司機（ACER_NB）跑完 Key_Management 掃描，回頭結掉 8/13 的待辦

接續下面 2026-08-13 那條的「等公司機跑過掃描再重比對」。公司機 `ACER_NB`（綁定身份 `Git_User1`）已掃描，`~/.key_management/registry.json` 有 6 筆、`seen_hosts` 全部只有 `ACER_NB`。

- **`MtN55…`（`kuoterry-git`，ed25519）確認有主，不撤。** 就是公司機 `C:\Users\kuote\.ssh\id_ed25519`，名冊 `first_seen` 2026-07-13。8/13 研判「是公司機的金鑰」正確。
- **`5yCe…`（`sshfs-nas`）與 `Znict…`（`rsa-key-20251211`）仍無主，維持不撤。** 公司機掃描後名冊裡沒有這兩把。但**跨機器同步至今沒有真的合併過家機的資料**（6 筆的 `seen_hosts` 都只有 `ACER_NB`，家機的 `bJM6…`/`Ejun…` 完全沒出現在名冊裡），所以「兩台都掃過了還是無主」這個結論**還不成立**，目前只證明了「不是公司機的」。撤銷前要先讓家機把名冊 push 上 NAS、公司機拉下來合併。
- 現況 `kuoterry` 的 authorized_keys 共 5 行：`5yCe…`(sshfs-nas)、`bJM6…`(sshfs-nas)、`Znict…`(rsa-key-20251211)、`Ejun…`(kuoterry@kcc3713.synology.me)、`MtN55…`(kuoterry-git)。唯讀 `cat` 取得，沒有做任何修改。

## 2026-08-14 — `git_user2` 的 authorized_keys 有兩把查無來源的金鑰（暫不處理）

Key_Management 對 `git_user2` 做 NAS 比對，3 行裡只有 1 行對得上本機（`xKlme…` = `id_ed25519_git_user2`），另外兩把 `jpGF…`、`UGd6…` 在**名冊、本機稽核紀錄、本機磁碟三處都查不到**。

- **暫不撤銷**，理由同上：家機名冊還沒合併進來，這兩把有可能是家機或 `git_user2` 私鑰持有者手上的金鑰。撤錯會直接鎖掉對方，而且沒有任何紀錄能還原是哪一把。
- **查不到不是意外，是工具的缺口**：`AddKeyForUserDialog`／`RotateKeyDialog` 只產生腳本、由人手貼到 SSH 視窗執行，不經 `Worker`，所以不在 `DESTRUCTIVE_MODES`、也沒有任何 `done` handler 會記——透過這兩條路加上去的金鑰在本機完全沒有痕跡。已於 v2.12.1 補上 `audit_key_script()`（記帳號＋指紋，狀態註明「腳本已產生，是否實際執行未知」）。`CreateGitDevsUserDialog`／`RemoveGitDevsUserDialog` 同一個缺口尚未補。
- 順帶查到：`id_ed25519_new`（`3zO/XFV…`，註解 `git_user2`）在 2026-07-15 就已從 **kuoterry**（不是 git_user2）的 authorized_keys 撤掉——稽核紀錄有 `ssh_keys_delete` 那筆，指紋比對吻合。跟 8/13 撤掉的 `Git_User1` 那把是同一種身份交叉，只是早一個月清掉。這把私鑰目前在公司機 `~/.ssh/` 閒置、名冊仍標 `active`（KM 的 status 只有 `active`/`missing` 兩種，沒有「已輪替/已作廢」，所以直接改名冊沒用，下次掃描會被覆寫回 `active`）；要退役得用 KM 的「封存（安全刪除）」把金鑰檔搬進封存區，下次掃描才會翻成 `missing` 並留下 history 事件。

## 2026-08-13 — 撤銷 kuoterry authorized_keys 中 Git_User1 的金鑰（身份交叉）

- **動作**：從 NAS `kuoterry` 的 `~/.ssh/authorized_keys` 移除指紋 `SHA256:CqIY44pKGw9E0adNCPyR8iN07WGOw3fCMOOuoeVsWjE`（註解 `Git_User1@kcc3713.synology.me`，RSA 4096）。手動 SSH 執行，比照工具慣例先備份：`authorized_keys.bak-20260813-204154`。
- **原因**：這是 Git_User1（公司身份）自己的金鑰，卻被授權登入 kuoterry（管理員帳號）——持有 Git_User1 私鑰即可直通 kuoterry，屬身份交叉，決定撤銷。來源不明（Key_Management 名冊與跨機器同步檔均無紀錄），推測為早期佈建時誤加。
- **驗證**：撤銷後 authorized_keys 剩 5 行（6→5），家機兩把常用金鑰（`bJM6…` id_ed25519、`Ejun…` id_rsa）確認仍在，連線正常；Key_Management 重跑比對結果一致。
- **待辦**：另外三把「只在 NAS」的 ❓ 金鑰（`5yCe…` sshfs-nas、`Znict…` rsa-key-20251211、`MtN55…` kuoterry-git）研判是公司機的金鑰，**先不撤**——等公司機跑過 Key_Management 掃描＋跨機器同步後重比對，屆時仍無主的才撤銷。

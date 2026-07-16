# sync-git-identity.ps1 使用說明

把一台電腦上所有 git repo 的 commit 作者身分統一成指定名字（例如公司機用 `Git_User1`、家用機用 `kuoterry`），讓 `git log` 本身就看得出這個 commit 是哪台機器做的，不用再對照伺服器端的 push log。

## 背景

`git config user.name`/`user.email` 有 global（整台機器預設）跟 local（單一 repo 覆蓋）兩層，local 會蓋掉 global。只改 global 沒用——如果某個 repo 之前自己另外設過 local 值，那個 repo 的 commit 作者還是會用舊的 local 值，看起來像沒生效。這支腳本做兩件事：

1. 設定 global `user.name`。
2. 掃描指定的 repo 根目錄，找出「還留著 local 覆蓋」的 repo 並列出來；加 `-Unset` 才會真的清掉，讓這些 repo 改吃 global。

`user.email` 不動，因為同一個人在不同機器用同一個 email 是合理的，要分辨的是「哪台機器」，不是「誰」。

## 用法

```powershell
# 只掃描、列出有 local 覆蓋的 repo，不改動任何東西
.\sync-git-identity.ps1 -Name "kuoterry"

# 確認列出的清單沒問題後，實際清掉 local 覆蓋
.\sync-git-identity.ps1 -Name "kuoterry" -Unset

# repo 不是放在預設的 D:\git / D:\GIT，自訂要掃描的根目錄
.\sync-git-identity.ps1 -Name "kuoterry" -Roots "D:\git","E:\projects" -Unset
```

## 參數

| 參數 | 必填 | 說明 |
|------|------|------|
| `-Name` | 是 | 要設定的 `user.name`，例如 `kuoterry`、`Git_User1` |
| `-Roots` | 否 | 要掃描的 repo 根目錄，可多個，預設 `D:\git`、`D:\GIT` |
| `-Unset` | 否 | 加了才會真的清掉找到的 local 覆蓋；不加只列出，不動任何 repo |

## 安全性

- 第一次執行**不要加 `-Unset`**，先看列出來的清單是不是預期的那些 repo。
- 只動 `user.name`/`user.email` 這兩個 key，不碰其他 local 設定（remote、branch 等都不會動到）。
- 每台機器各自執行、各自傳自己的 `-Name`（公司機傳 `Git_User1`，家用機傳 `kuoterry`），不要在同一台機器上跑錯身分。

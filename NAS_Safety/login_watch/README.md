# login_watch

監控 Synology DSM（DS418, DSM 7.3.2 測試過）的成功登入事件：紀錄成 JSONL 檔，並在偵測到新登入時寄一封彙整通知（email + Telegram）。

## 運作原理

- 資料來源是 DSM 內部的連線紀錄資料庫 `/var/log/synolog/.SYNOCONNDB`（sqlite3，table 名為 `logs`），
  這是 DSM Log Center「連線紀錄」畫面背後的實際儲存位置，欄位包含 `id`, `time`, `level`, `username`, `ip`,
  `protocol`, `msg`。這個格式沒有官方文件，是直接連進這台 NAS 查出來的，**DSM 大版本升級後可能改變**，
  升級後建議重跑一次 README 最後「驗證」那一步確認欄位還一致。
- 判斷「成功登入」的規則：`level = 'info'` 且 `msg` 內含 `"logged in successfully via"`。這個規則涵蓋
  DSM 網頁、SSH、FTP、SMB/CIFS、WebDAV 等各種登入方式,只要 DSM 用同一套訊息樣板記錄。
- 地理位置查詢完全離線：用 MaxMind GeoLite2-City 的 CSV 版本自建一個本機 sqlite 對照表，不會把任何登入者
  IP 送到外部服務。目前只支援 IPv4；區網（私有位址）直接標記「區域網路（內部）」，不查資料庫。
- 每次執行只處理「上次執行之後」的新紀錄（用 `state.json` 記住處理到哪個 `id`），不會重複通知，
  第一次執行只會記錄當下最新的 id 當作起點，不會把過去的登入歷史全部通知一次。
- 通知走兩個獨立管道：email（讀 `config.json` 的 `smtp` 區塊）與 Telegram（讀
  `/volume1/Git_Server/config/tg_bot.conf`，跟 NAS_GIT_Tools 專案管理的 CI 引擎/鏡像同步共用同一份
  Bot 設定，不在這裡另存一份）。兩個管道各自獨立失敗不互相影響，任一個沒設定就單純略過那個管道。

## 部署位置（重要）

DSM 開機時會顯示警告：「Data should only be stored in shared folders. Data stored elsewhere may be deleted
when the system is updated/restarted.」所以這個資料夾**必須放在共用資料夾底下**，例如：

```
/volume1/homes/kuoterry/NAS_Safety/login_watch/
```

不要放在 `/root`、`/usr/local` 之類的系統路徑，DSM 更新有可能把它清掉。

## 部署步驟

1. 把整個 repo（或至少 `login_watch/` 這個資料夾）複製到 NAS 上的共用資料夾路徑，例如上面那個路徑。

2. 複製設定檔範本並填入實際值：
   ```
   cp config.example.json config.json
   ```
   打開 `config.json`，把 `smtp` 區塊改成 DSM「控制台 → 通知 → 電子郵件」裡已經在用的同一組 SMTP
   設定（host/port/帳號/密碼），`to_addrs` 填你要收通知的信箱。`config.json` 已加進 `.gitignore`，
   不會被提交，但檔案本身建議 `chmod 600`。

3. 到 [MaxMind GeoLite2 免費註冊頁面](https://www.maxmind.com/en/geolite2/signup) 申請免費帳號並取得
   license key，下載 **GeoLite2 City** 的 **CSV** 格式（不是 mmdb binary，因為這台 NAS 的 python3
   沒有 pip，無法裝 geoip2/maxminddb 套件）。解壓縮後，把裡面的
   `GeoLite2-City-Blocks-IPv4.csv` 和 `GeoLite2-City-Locations-en.csv` 兩個檔案放到：
   ```
   login_watch/geoip_src/
   ```

4. 在 NAS 上（SSH，root 權限）建立本機地理位置資料庫，只需執行一次，之後要更新 GeoLite2 資料時再重跑：
   ```
   cd /volume1/homes/kuoterry/NAS_Safety/login_watch
   python3 build_geoip_db.py
   ```
   完成後會產生 `geoip.sqlite3`（同樣已加進 `.gitignore`）。

5. 手動跑一次確認第一次執行的「起始化」行為（不應該寄信，只會建立 `state.json`）：
   ```
   python3 login_watch.py
   ```
   應該會印出類似「首次執行，記錄目前最新的登入紀錄 id = N，之後只會通知新的登入。」。

6. 驗證：從另一個裝置/網路實際登入一次 NAS（例如 SSH 或 DSM 網頁），然後再手動執行一次
   `python3 login_watch.py`，確認：
   - `logs/login_events.jsonl` 多了一行，內容包含帳號、IP、地理位置。
   - 有收到通知信；若 `/volume1/Git_Server/config/tg_bot.conf` 已設定好 Telegram Bot，也應該收到
     Telegram 訊息（兩個管道互相獨立，缺一個不影響另一個）。

7. 排程：DSM 控制台 → 工作排程器 → 新增 → 觸發的任務 → 使用者定義的指令碼：
   - 使用者：`root`（因為 `.SYNOCONNDB` 只有 root/system 可讀）
   - 排程：例如每 5 分鐘一次
   - 執行指令：
     ```
     python3 /volume1/homes/kuoterry/NAS_Safety/login_watch/login_watch.py
     ```

## 已知限制

- 只支援 IPv4 地理位置查詢；IPv6 登入者會記錄 IP，但位置欄位顯示「不支援 IPv6」。
- 判斷邏輯依賴 DSM 內部訊息樣板字串，不是官方公開 API，DSM 版本更新後有失效風險。
- GeoLite2 CSV 資料庫是 MaxMind 定期更新的免費資料庫，準確度以城市等級為主，非即時、非百分之百精確。

"""
監控 Synology DSM 的成功登入事件，記錄成 JSONL 檔並寄送通知信（email + Telegram）。

用法（在 NAS 上以 root 執行，通常透過 DSM Task Scheduler 排程呼叫）：
    python3 login_watch.py [config.json 路徑，預設為本檔案同目錄的 config.json]

資料來源：
    DSM 的連線紀錄資料庫 /var/log/synolog/.SYNOCONNDB（sqlite3，table 名為 logs）。
    這是未公開文件化的內部格式，若 DSM 大版本更新後欄位或訊息格式改變，需要重新確認。

通知管道：
    Email 走 config.json 裡的 smtp 設定；Telegram 沿用 NAS_GIT_Tools 專案管理的
    共用設定檔 /volume1/Git_Server/config/tg_bot.conf（BOT_TOKEN=/CHAT_ID=），
    避免同一組 Telegram Bot 憑證在兩個專案裡各存一份。兩個管道彼此獨立，任一個
    沒設定或失敗都不影響另一個。
"""

import ipaddress
import json
import smtplib
import sqlite3
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
TELEGRAM_CONFIG_PATH = Path("/volume1/Git_Server/config/tg_bot.conf")


def load_config(config_path):
    """
    讀取設定檔。

    參數:
        config_path (Path): config.json 的路徑。

    依賴: 標準庫 json。

    回傳:
        dict: 設定內容，欄位見 config.example.json。
    """
    with open(config_path, "r", encoding="utf-8") as config_file:
        return json.load(config_file)


def resolve_path(base_dir, path_value):
    """
    把設定檔裡的相對路徑，轉成相對於 config.json 所在目錄的絕對路徑。

    參數:
        base_dir (Path): config.json 所在的目錄。
        path_value (str): 設定檔裡的路徑字串，可為相對或絕對路徑。

    依賴: 標準庫 pathlib。

    回傳:
        Path: 絕對路徑。
    """
    candidate_path = Path(path_value)
    if candidate_path.is_absolute():
        return candidate_path
    return (base_dir / candidate_path).resolve()


def get_last_processed_id(state_path):
    """
    讀取上次處理到的最後一筆登入紀錄 id。

    參數:
        state_path (Path): state.json 的路徑。

    依賴: 標準庫 json。

    回傳:
        int | None: 上次處理到的 id；若狀態檔不存在（代表第一次執行），回傳 None。
    """
    if not state_path.exists():
        return None
    with open(state_path, "r", encoding="utf-8") as state_file:
        state_data = json.load(state_file)
    return state_data.get("last_processed_id")


def save_last_processed_id(state_path, last_processed_id):
    """
    把最後處理到的登入紀錄 id 寫回狀態檔。

    參數:
        state_path (Path): state.json 的路徑。
        last_processed_id (int): 這次執行後最新處理到的 id。

    依賴: 標準庫 json、pathlib。

    回傳:
        None
    """
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as state_file:
        json.dump({"last_processed_id": last_processed_id}, state_file, ensure_ascii=False, indent=2)


def get_max_log_id(conn_db_path):
    """
    查詢連線紀錄資料庫目前最新的 id，用於第一次執行時的起始點（不補歷史通知）。

    參數:
        conn_db_path (Path): DSM 連線紀錄 sqlite 資料庫路徑（.SYNOCONNDB）。

    依賴: 標準庫 sqlite3；需要有讀取 conn_db_path 的權限（通常需要 root）。

    回傳:
        int: 目前資料表中最大的 id；若資料表是空的，回傳 0。
    """
    connection = sqlite3.connect(f"file:{conn_db_path}?mode=ro", uri=True)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT MAX(id) FROM logs")
        max_id = cursor.fetchone()[0]
        return max_id if max_id is not None else 0
    finally:
        connection.close()


def fetch_new_logins(conn_db_path, since_id):
    """
    查詢連線紀錄資料庫，取出所有 id 大於 since_id 的「成功登入」事件。

    參數:
        conn_db_path (Path): DSM 連線紀錄 sqlite 資料庫路徑（.SYNOCONNDB）。
        since_id (int): 只取這個 id 之後（不含）的紀錄，用於避免重複處理。

    依賴: 標準庫 sqlite3；需要有讀取 conn_db_path 的權限（通常需要 root）。

    回傳:
        list[dict]: 每筆為 {"id": int, "time": int, "username": str, "ip": str,
        "protocol": str, "msg": str}，依 id 由小到大排序。
    """
    connection = sqlite3.connect(f"file:{conn_db_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, time, username, ip, protocol, msg
            FROM logs
            WHERE level = 'info'
              AND msg LIKE '%logged in successfully via%'
              AND id > ?
            ORDER BY id ASC
            """,
            (since_id,),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        connection.close()


def lookup_location(geoip_db_path, ip_text):
    """
    把來源 IP 轉成地理位置描述文字。私有網段（區域網路）直接標記，不查資料庫；
    IPv6 位址目前不支援查詢；其餘走本機離線 GeoLite2 資料庫（geoip.sqlite3）。

    參數:
        geoip_db_path (Path): build_geoip_db.py 產生的 geoip.sqlite3 路徑。
        ip_text (str): 來源 IP 位址字串。

    依賴: 標準庫 ipaddress、sqlite3；需要事先執行過 build_geoip_db.py。

    回傳:
        str: 人類可讀的地理位置描述，例如 "台灣, 台北" 或 "區域網路（內部）" 或 "未知位置"。
    """
    try:
        ip_address = ipaddress.ip_address(ip_text)
    except ValueError:
        return "未知位置（IP 格式無法解析）"

    if ip_address.is_private or ip_address.is_loopback or ip_address.is_link_local:
        return "區域網路（內部）"

    if ip_address.version != 4:
        return "未知位置（目前不支援 IPv6 地理查詢）"

    if not geoip_db_path.exists():
        return "未知位置（尚未建立 geoip.sqlite3，請先執行 build_geoip_db.py）"

    ip_as_int = int(ip_address)
    connection = sqlite3.connect(f"file:{geoip_db_path}?mode=ro", uri=True)
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT country, city, end_int
            FROM ranges
            WHERE start_int <= ?
            ORDER BY start_int DESC
            LIMIT 1
            """,
            (ip_as_int,),
        )
        row = cursor.fetchone()
    finally:
        connection.close()

    if row is None:
        return "未知位置（查無資料）"

    country, city, end_int = row
    if end_int < ip_as_int:
        return "未知位置（查無資料）"

    location_parts = [part for part in (country, city) if part]
    return "、".join(location_parts) if location_parts else "未知位置（查無資料）"


def format_record(row, location):
    """
    把一筆原始登入紀錄整理成要寫入 JSONL 檔的結構化紀錄。

    參數:
        row (dict): fetch_new_logins() 回傳的單筆原始紀錄。
        location (str): lookup_location() 回傳的地理位置描述。

    依賴: 標準庫 datetime。

    回傳:
        dict: {"id", "time_iso", "username", "ip", "protocol", "location", "raw_msg"}。
    """
    login_time = datetime.fromtimestamp(row["time"])
    return {
        "id": row["id"],
        "time_iso": login_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": row["username"],
        "ip": row["ip"],
        "protocol": row["protocol"],
        "location": location,
        "raw_msg": row["msg"],
    }


def append_jsonl(log_file_path, record):
    """
    把一筆結構化紀錄以 JSON Lines 格式附加寫入紀錄檔。

    參數:
        log_file_path (Path): 紀錄檔路徑（例如 logs/login_events.jsonl）。
        record (dict): format_record() 產生的紀錄。

    依賴: 標準庫 json、pathlib。

    回傳:
        None
    """
    log_file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_email_body(records):
    """
    把多筆登入紀錄組成一封通知信的主旨與內文。

    參數:
        records (list[dict]): format_record() 產生的紀錄列表，至少一筆。

    依賴: 無外部依賴。

    回傳:
        tuple[str, str]: (subject, body)。
    """
    subject = f"[NAS 登入通知] 偵測到 {len(records)} 筆新的成功登入"
    lines = [
        f"時間: {record['time_iso']}  帳號: {record['username']}  "
        f"IP: {record['ip']}  位置: {record['location']}  方式: {record['protocol']}"
        for record in records
    ]
    body = "\n".join(lines)
    return subject, body


def send_email(smtp_config, subject, body):
    """
    透過 SMTP 寄送純文字通知信。

    參數:
        smtp_config (dict): {"host", "port", "use_tls", "username", "password",
        "from_addr", "to_addrs"}，其中 to_addrs 為字串陣列。
        subject (str): 信件主旨。
        body (str): 信件純文字內文。

    依賴: 標準庫 smtplib、email.mime.text；需要設定檔提供可用的 SMTP 帳號。

    回傳:
        None

    例外:
        若連線或驗證失敗會拋出 smtplib 的例外，由呼叫端決定如何處理。
    """
    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject
    message["From"] = smtp_config["from_addr"]
    message["To"] = ", ".join(smtp_config["to_addrs"])

    with smtplib.SMTP(smtp_config["host"], smtp_config["port"], timeout=30) as server:
        if smtp_config.get("use_tls", True):
            server.starttls()
        server.login(smtp_config["username"], smtp_config["password"])
        server.sendmail(smtp_config["from_addr"], smtp_config["to_addrs"], message.as_string())


def load_telegram_config(config_path):
    """
    讀取共用的 Telegram 設定（沿用 NAS_GIT_Tools 專案管理的 config/tg_bot.conf）。

    參數:
        config_path (Path): tg_bot.conf 的路徑，內容為逐行的 BOT_TOKEN=.../CHAT_ID=...。

    依賴: 標準庫 pathlib。

    回傳:
        tuple[str, str] | None: (bot_token, chat_id)；若設定檔不存在或欄位空白，回傳 None。
    """
    if not config_path.exists():
        return None
    bot_token = ""
    chat_id = ""
    for line in config_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("BOT_TOKEN="):
            bot_token = line[len("BOT_TOKEN="):].strip()
        elif line.startswith("CHAT_ID="):
            chat_id = line[len("CHAT_ID="):].strip()
    if not bot_token or not chat_id:
        return None
    return bot_token, chat_id


def send_telegram(bot_token, chat_id, text):
    """
    透過 Telegram Bot API 寄送純文字通知。

    參數:
        bot_token (str): Telegram Bot Token。
        chat_id (str): 要通知的 chat id。
        text (str): 通知內容。

    依賴: 標準庫 urllib.request、urllib.parse（這台 NAS 的 python3 沒有 pip，
    不能裝 requests，所以只用標準庫）。

    回傳:
        None

    例外:
        若連線失敗會拋出 urllib 的例外，由呼叫端決定如何處理。
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    with urllib.request.urlopen(url, data=data, timeout=30):
        pass


def main():
    """
    主流程：讀設定 -> 找出上次處理到哪裡 -> 撈新的成功登入事件 -> 逐筆查地理位置並寫入
    JSONL 紀錄檔 -> 若有新事件就寄一封彙整通知信 -> 更新狀態檔。

    參數: 無（透過 sys.argv[1] 可選擇指定 config.json 路徑，預設為本檔案同目錄）。

    依賴: 本檔案內其餘所有函式。

    回傳:
        None（執行失敗時以 sys.exit(1) 結束，供 Task Scheduler 判斷成敗）。
    """
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else SCRIPT_DIR / "config.json"
    if not config_path.exists():
        print(f"錯誤: 找不到設定檔 {config_path}", file=sys.stderr)
        sys.exit(1)

    config = load_config(config_path)
    base_dir = config_path.parent

    conn_db_path = resolve_path(base_dir, config["conn_db_path"])
    state_path = resolve_path(base_dir, config["state_file"])
    log_file_path = resolve_path(base_dir, config["log_file"])
    geoip_db_path = resolve_path(base_dir, config["geoip_db_path"])

    try:
        last_processed_id = get_last_processed_id(state_path)
        if last_processed_id is None:
            bootstrap_id = get_max_log_id(conn_db_path)
            save_last_processed_id(state_path, bootstrap_id)
            print(f"首次執行，記錄目前最新的登入紀錄 id = {bootstrap_id}，之後只會通知新的登入。")
            return

        new_logins = fetch_new_logins(conn_db_path, last_processed_id)
    except sqlite3.Error as error:
        print(f"錯誤: 讀取連線紀錄資料庫失敗: {error}", file=sys.stderr)
        sys.exit(1)

    if not new_logins:
        return

    records = []
    for row in new_logins:
        location = lookup_location(geoip_db_path, row["ip"])
        record = format_record(row, location)
        append_jsonl(log_file_path, record)
        records.append(record)

    subject, body = build_email_body(records)

    smtp_config = config.get("smtp")
    if smtp_config and smtp_config.get("enabled", True):
        try:
            send_email(smtp_config, subject, body)
        except Exception as error:
            print(f"警告: 通知信寄送失敗，但紀錄已寫入 {log_file_path}: {error}", file=sys.stderr)

    telegram_config = load_telegram_config(TELEGRAM_CONFIG_PATH)
    if telegram_config:
        bot_token, chat_id = telegram_config
        try:
            send_telegram(bot_token, chat_id, f"{subject}\n{body}")
        except Exception as error:
            print(f"警告: Telegram 通知寄送失敗，但紀錄已寫入 {log_file_path}: {error}", file=sys.stderr)

    save_last_processed_id(state_path, records[-1]["id"])
    print(f"處理完成，新增 {len(records)} 筆登入紀錄。")


if __name__ == "__main__":
    main()

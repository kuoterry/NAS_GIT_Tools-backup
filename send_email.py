"""
共用寄信小工具：讀取 login_watch 專案既有的 SMTP 設定，寄送純文字通知信。

給 NAS 上其他 bash 腳本（例如 ci_daily_violation_report.sh、git_stats_report.sh）
在完成 Telegram 通知後，順便呼叫這支腳本補發一封 email。

用法：
    echo "信件內文" | python3 send_email.py --subject "信件主旨"
"""

import argparse
import json
import smtplib
import sys
from email.mime.text import MIMEText
from pathlib import Path

SMTP_CONFIG_PATH = Path("/volume1/NAS_Safety/login_watch/config.json")


def load_smtp_config(config_path):
    """
    讀取共用的 SMTP 設定（沿用 login_watch 專案的 config.json，避免同一組帳密重複維護兩份）。

    參數:
        config_path (Path): login_watch 的 config.json 路徑。

    依賴: 標準庫 json、pathlib。

    回傳:
        dict | None: smtp 設定區塊（見 login_watch/config.example.json）；
        若設定檔不存在或 smtp 區塊未啟用，回傳 None。
    """
    if not config_path.exists():
        return None
    with open(config_path, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)
    smtp_config = config.get("smtp")
    if not smtp_config or not smtp_config.get("enabled", True):
        return None
    return smtp_config


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


def main():
    """
    主流程：解析 --subject 參數、從 stdin 讀取信件內文、寄出。

    參數: 無（命令列 --subject 為必填；信件內文從 stdin 讀取）。

    依賴: 本檔案內其餘所有函式。

    回傳:
        None。找不到/未啟用 SMTP 設定，或寄送失敗時，只印警告訊息到 stderr 並以
        exit code 0 結束，不讓呼叫端的 bash 腳本因為寄信失敗而被判定整體失敗。
    """
    parser = argparse.ArgumentParser(description="寄送純文字通知信，SMTP 設定沿用 login_watch 專案。")
    parser.add_argument("--subject", required=True, help="信件主旨")
    args = parser.parse_args()

    body = sys.stdin.read()

    smtp_config = load_smtp_config(SMTP_CONFIG_PATH)
    if smtp_config is None:
        print(f"警告: 找不到或未啟用 SMTP 設定（{SMTP_CONFIG_PATH}），略過寄信。", file=sys.stderr)
        return

    try:
        send_email(smtp_config, args.subject, body)
    except Exception as error:
        print(f"警告: 寄信失敗: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()

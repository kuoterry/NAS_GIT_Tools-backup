#!/bin/bash
# =====================================================
# git_stats_report.sh
# Repo / User / Branch 統計排行榜
# =====================================================

BASE="/volume1/Git_Server"
CONF="$BASE/config/tg_bot.conf"   # 與 CI 引擎、鏡像同步腳本共用同一份 Telegram 設定

BOT_TOKEN=""; CHAT_ID=""
[ -f "$CONF" ] && . "$CONF"

LOG="/volume1/Git_Server/logs/git_push.log"
TODAY=$(date '+%Y-%m-%d')

if [ ! -f "$LOG" ]; then
    MSG="📊 Git 統計排行榜 ($TODAY)
❌ 找不到 log 檔案"
else
    TOTAL=$(grep "^$TODAY" "$LOG" | wc -l)

    REPO_TOP=$(grep "^$TODAY" "$LOG" \
        | awk -F'|' '{print $3}' \
        | sed 's/^ *//;s/ *$//' \
        | sort | uniq -c | sort -nr | head -5)

    USER_TOP=$(grep "^$TODAY" "$LOG" \
        | awk -F'|' '{print $2}' \
        | sed 's/^ *//;s/ *$//' \
        | sort | uniq -c | sort -nr | head -5)

    BRANCH_TOP=$(grep "^$TODAY" "$LOG" \
        | awk -F'|' '{print $4}' \
        | sed 's/^ *//;s/ *$//' \
        | sort | uniq -c | sort -nr | head -5)

    MSG="📊 Git 今日統計排行榜 ($TODAY)
📦 總推送次數: $TOTAL

🏆 Repo Top 5:
$REPO_TOP

👤 User Top 5:
$USER_TOP

🌳 Branch Top 5:
$BRANCH_TOP"
fi

if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    curl -s "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
      --data-urlencode "chat_id=$CHAT_ID" \
      --data-urlencode "text=$MSG" \
      >/dev/null 2>&1
fi

echo "$MSG" | python3 "$BASE/tools/send_email.py" --subject "Git 今日統計排行榜 ($TODAY)"

exit 0

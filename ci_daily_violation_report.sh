#!/bin/bash
# =====================================================
# ci_daily_violation_report.sh
# CI 違規每日彙總
# =====================================================

BASE="/volume1/Git_Server"
CONF="$BASE/config/tg_bot.conf"   # 與 CI 引擎、鏡像同步腳本共用同一份 Telegram 設定

BOT_TOKEN=""; CHAT_ID=""
[ -f "$CONF" ] && . "$CONF"

LOG="/volume1/Git_Server/logs/ci_violation.log"
TODAY=$(date '+%Y-%m-%d')

if [ ! -f "$LOG" ]; then
    MSG="🚨 CI 違規報告 ($TODAY)
🎉 今日沒有任何 CI 違規"
else
    COUNT=$(grep "^$TODAY" "$LOG" | wc -l)

    if [ "$COUNT" -eq 0 ]; then
        MSG="🚨 CI 違規報告 ($TODAY)
🎉 今日沒有任何 CI 違規"
    else
        BY_REPO=$(grep "^$TODAY" "$LOG" \
            | awk -F'|' '{print $2}' \
            | sed 's/^ *//;s/ *$//' \
            | sort | uniq -c | sort -nr)

        MSG="🚨 CI 違規報告 ($TODAY)
❌ 違規次數: $COUNT

📦 Repo 違規統計:
$BY_REPO"
    fi
fi

if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    curl -s "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
      --data-urlencode "chat_id=$CHAT_ID" \
      --data-urlencode "text=$MSG" \
      >/dev/null 2>&1
fi

echo "$MSG" | python3 "$BASE/tools/send_email.py" --subject "CI 違規報告 ($TODAY)"

exit 0

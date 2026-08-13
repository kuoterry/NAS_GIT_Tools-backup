#!/bin/bash
# =====================================================
# nas_git_healthcheck.sh
#   排程版輕量健檢：GUI 健康檢查的「會過期、需要人盯」子集
#   - 鏡像庫同步新鮮度（FETCH_HEAD ≥14 天沒動）
#   - 離站備份新鮮度（nasgit.lastbackup 缺失或 ≥14 天，含 _archived/ 內的 bare repo）
#   - 磁碟使用率 ≥90%
#   完整健檢（hook/群組/ACL/drift…）仍走 GUI 的「健康檢查」按鈕。
#
#   設計：只有「有異常」才發 Telegram/email，全部正常時安靜結束（每天一封
#   「一切正常」的通知只會訓練人忽略通知）。log 則每次都寫，留存活證據。
#
# 用法：
#   bash /volume1/Git_Server/tools/nas_git_healthcheck.sh
# 建議：DS418 控制台 → 任務排程表 → 每日排程執行本腳本
# =====================================================

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

BASE="/volume1/Git_Server"
LOG="$BASE/logs/healthcheck.log"
CONF="$BASE/config/tg_bot.conf"   # 選用：內含 BOT_TOKEN= 與 CHAT_ID=
STALE_DAYS=14
DISK_WARN_PCT=90

mkdir -p "$BASE/logs"

BOT_TOKEN=""; CHAT_ID=""
[ -f "$CONF" ] && . "$CONF"

now() { date '+%Y-%m-%d %H:%M:%S'; }
NOW_EPOCH=$(date +%s)

WARN_LIST=""
N_WARN=0

warn() {
    echo "$(now) | WARN | $1" >> "$LOG"
    WARN_LIST="$WARN_LIST"$'\n'"⚠ $1"
    N_WARN=$((N_WARN+1))
}

# --- 鏡像庫同步新鮮度 ---
for repo in "$BASE"/*.git; do
    [ -d "$repo" ] || continue
    [ "$(git --git-dir="$repo" config --get remote.origin.mirror 2>/dev/null)" = "true" ] || continue
    name=$(basename "$repo")
    ts=$(stat -c %Y "$repo/FETCH_HEAD" 2>/dev/null)
    if [ -z "$ts" ]; then
        warn "鏡像 $name：找不到 FETCH_HEAD（從未同步過？）"
    elif [ $(( (NOW_EPOCH - ts) / 86400 )) -ge "$STALE_DAYS" ]; then
        warn "鏡像 $name：已 $(( (NOW_EPOCH - ts) / 86400 )) 天沒同步"
    fi
done

# --- 離站備份新鮮度（活庫 + 封存區 bare repo，涵蓋範圍與同步一致）---
check_backup() {
    repo="$1"; name="$2"
    url=$(git --git-dir="$repo" config --get remote.offsite-backup.url 2>/dev/null)
    [ -n "$url" ] || return 0
    last=$(git --git-dir="$repo" config --get nasgit.lastbackup 2>/dev/null)
    if [ -z "$last" ]; then
        warn "離站備份 $name：設定了備份但沒有成功推送的時戳"
    elif [ $(( (NOW_EPOCH - last) / 86400 )) -ge "$STALE_DAYS" ]; then
        warn "離站備份 $name：已 $(( (NOW_EPOCH - last) / 86400 )) 天沒成功推送"
    fi
}
for repo in "$BASE"/*.git; do
    [ -d "$repo" ] || continue
    check_backup "$repo" "$(basename "$repo")"
done
for arch in "$BASE"/_archived/*; do
    [ -d "$arch" ] || continue
    [ -e "$arch/HEAD" ] || continue
    check_backup "$arch" "_archived/$(basename "$arch")"
done

# --- 磁碟使用率 ---
PCT=$(df -P "$BASE" 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}')
if [ -z "$PCT" ]; then
    warn "讀不到磁碟使用率，無法確認"
elif [ "$PCT" -ge "$DISK_WARN_PCT" ] 2>/dev/null; then
    warn "磁碟使用率已達 ${PCT}%"
fi

echo "$(now) | 完成：$N_WARN 項警告" >> "$LOG"

# 全部正常 → 安靜結束
[ "$N_WARN" -eq 0 ] && exit 0

MSG="🩺 NAS Git 排程健檢（$(now)）
共 $N_WARN 項警告：$WARN_LIST"

# Telegram（有設定才發）
if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        --data-urlencode "chat_id=$CHAT_ID" \
        --data-urlencode "text=$MSG" >/dev/null 2>&1
fi

# email（send_email.py 缺設定/失敗自己 exit 0，不會擋住這裡）
if [ -f "$BASE/tools/send_email.py" ]; then
    echo "$MSG" | python3 "$BASE/tools/send_email.py" --subject "NAS Git 排程健檢：$N_WARN 項警告" >/dev/null 2>&1
fi

exit 1

#!/bin/bash
# =====================================================
# offsite_backup_sync.sh
#   自動同步 NAS 上所有「設定了離站備份」的 bare repo 到外部 Git 端點
#   - 只處理 remote.offsite-backup.url 有設定的庫（GUI「離站備份…」設的那個 remote）
#   - 也涵蓋 _archived/ 內仍是 bare repo 的封存項目（mv 封存時 remote 設定跟著搬進去）
#     （.tar.gz 形式的封存與從未設定離站備份的庫不在涵蓋範圍，健檢報表會提醒）
#   - git push --mirror：目的端逐 byte 對齊本庫（含刪除目的端多出來的分支/tag），
#     所以目的端必須是專用備份庫，不能是還有人推的活庫
#   - 成功才蓋 nasgit.lastbackup 時戳（健檢靠它抓「設了備份卻沒推成功過」）
#   - Telegram 通知為選用：從設定檔讀，沒有就安靜略過（不寫死 Token）
#
# 用法：
#   bash /volume1/Git_Server/tools/offsite_backup_sync.sh
# 建議：DS418 控制台 → 任務排程表 → 每日排程執行本腳本
#   （GUI 的「同步離站備份」按鈕是同一套邏輯的手動版）
# =====================================================

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

BASE="/volume1/Git_Server"
LOG="$BASE/logs/offsite_backup.log"
CONF="$BASE/config/tg_bot.conf"   # 選用：內含 BOT_TOKEN= 與 CHAT_ID=

mkdir -p "$BASE/logs"

# 讀取 Telegram 設定（存在才啟用通知）
BOT_TOKEN=""; CHAT_ID=""
[ -f "$CONF" ] && . "$CONF"

now() { date '+%Y-%m-%d %H:%M:%S'; }

OK_LIST=""
FAIL_LIST=""
N_OK=0
N_FAIL=0

# sync_one <git-dir> <顯示名稱>
sync_one() {
    repo="$1"; name="$2"
    url=$(git --git-dir="$repo" config --get remote.offsite-backup.url 2>/dev/null)
    [ -n "$url" ] || return 0

    if git --git-dir="$repo" push --mirror offsite-backup >/dev/null 2>&1; then
        git --git-dir="$repo" config nasgit.lastbackup "$(date +%s)" 2>/dev/null
        echo "$(now) | OK   | $name | $url" >> "$LOG"
        OK_LIST="$OK_LIST"$'\n'"✅ $name"
        N_OK=$((N_OK+1))
    else
        echo "$(now) | FAIL | $name | $url" >> "$LOG"
        FAIL_LIST="$FAIL_LIST"$'\n'"❌ $name"
        N_FAIL=$((N_FAIL+1))
    fi
}

# 活庫
for repo in "$BASE"/*.git; do
    [ -d "$repo" ] || continue
    sync_one "$repo" "$(basename "$repo")"
done

# 封存區內仍是 bare repo 的項目（HEAD 存在才算；tar.gz 略過）
for arch in "$BASE"/_archived/*; do
    [ -d "$arch" ] || continue
    [ -e "$arch/HEAD" ] || continue
    sync_one "$arch" "_archived/$(basename "$arch")"
done

TOTAL=$((N_OK+N_FAIL))
echo "$(now) | 完成：共 $TOTAL 個備份目標，成功 $N_OK，失敗 $N_FAIL" >> "$LOG"

# 沒有任何設定離站備份的庫就安靜結束
[ "$TOTAL" -eq 0 ] && exit 0

# Telegram 通知（僅在有設定時）
if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    MSG="🛡 離站備份同步（$(now)）
成功 $N_OK / 失敗 $N_FAIL$OK_LIST$FAIL_LIST"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        --data-urlencode "chat_id=$CHAT_ID" \
        --data-urlencode "text=$MSG" >/dev/null 2>&1
fi

# 有失敗回傳非 0，方便排程器記錄
[ "$N_FAIL" -gt 0 ] && exit 1
exit 0

#!/bin/bash
# =====================================================
# sync_github_mirrors.sh
#   自動同步 NAS 上「所有 GitHub 鏡像庫」（--mirror clone 出來的 bare repo）
#   - 只處理 remote.origin.mirror=true 的庫，一般庫略過
#   - remote update --prune：抓上游最新分支/tag，並清掉上游已刪的
#   - Telegram 通知為選用：從設定檔讀，沒有就安靜略過（不寫死 Token）
#
# 用法：
#   bash /volume1/Git_Server/tools/sync_github_mirrors.sh
# 建議：DS418 控制台 → 任務排程表 → 每日排程執行本腳本
# =====================================================

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

BASE="/volume1/Git_Server"
LOG="$BASE/logs/mirror_sync.log"
CONF="$BASE/config/tg_bot.conf"   # 選用：內含 BOT_TOKEN= 與 CHAT_ID=

mkdir -p "$BASE/logs"

# 互斥鎖：上一輪還在跑（大庫＋慢網路可能超過排程間隔）就直接讓路，
# 兩份 remote update 同時打同一個 bare repo 的失敗很難事後診斷。
# mkdir 是原子操作，BusyBox 也適用，不需要 flock。
LOCK="$BASE/.lock-mirror_sync"
if ! mkdir "$LOCK" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') | SKIP | 上一輪還在跑（$LOCK 存在），本輪略過" >> "$LOG"
    exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

# 讀取 Telegram 設定（存在才啟用通知）
BOT_TOKEN=""; CHAT_ID=""
[ -f "$CONF" ] && . "$CONF"

now() { date '+%Y-%m-%d %H:%M:%S'; }

OK_LIST=""
FAIL_LIST=""
N_OK=0
N_FAIL=0

for repo in "$BASE"/*.git; do
    [ -d "$repo" ] || continue

    # 只處理「鏡像」庫
    ismir=$(git --git-dir="$repo" config --get remote.origin.mirror 2>/dev/null)
    [ "$ismir" = "true" ] || continue

    name=$(basename "$repo")
    url=$(git --git-dir="$repo" config --get remote.origin.url 2>/dev/null)

    if git --git-dir="$repo" remote update --prune >/dev/null 2>&1; then
        echo "$(now) | OK   | $name | $url" >> "$LOG"
        OK_LIST="$OK_LIST"$'\n'"✅ $name"
        N_OK=$((N_OK+1))
    else
        echo "$(now) | FAIL | $name | $url" >> "$LOG"
        FAIL_LIST="$FAIL_LIST"$'\n'"❌ $name"
        N_FAIL=$((N_FAIL+1))
    fi
done

TOTAL=$((N_OK+N_FAIL))
echo "$(now) | 完成：共 $TOTAL 個鏡像，成功 $N_OK，失敗 $N_FAIL" >> "$LOG"

# 沒有任何鏡像庫就安靜結束
[ "$TOTAL" -eq 0 ] && exit 0

# Telegram 通知（僅在有設定、且有失敗或有成功時）
if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    MSG="🔄 GitHub 鏡像同步（$(now)）
成功 $N_OK / 失敗 $N_FAIL$OK_LIST$FAIL_LIST"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        --data-urlencode "chat_id=$CHAT_ID" \
        --data-urlencode "text=$MSG" >/dev/null 2>&1
fi

# 有失敗回傳非 0，方便排程器記錄
[ "$N_FAIL" -gt 0 ] && exit 1
exit 0

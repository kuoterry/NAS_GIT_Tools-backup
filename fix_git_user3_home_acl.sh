#!/bin/bash
# 一次性診斷 + 修復腳本：git_user3 SSH 金鑰登入失敗。
# 用 kuoterry 身分 SSH 進 NAS 後貼上整段執行（單一 sudo -v 檢查點，其餘不互動）。
# 根因參考 CLAUDE.md「Incident (2026-07-15)」：DSM sshd 會因 home 目錄本身的
# Synology ACL 非 trivial 而靜默丟棄整份 authorized_keys，看起來像金鑰錯但其實
# 金鑰設定完全正確。git_user3 建立於 2026-07-11（該 ACL 修法 07-15 才補進生成
# script），所以從未套用過這個修復。

sudo -v

USERNAME="git_user3"
HOME_DIR="$(grep "^${USERNAME}:" /etc/passwd | cut -d: -f6)"
if [ -z "$HOME_DIR" ]; then
    echo "‼️ 找不到帳號 $USERNAME，先確認帳號是否存在"
    exit 1
fi
echo "HOME_DIR=$HOME_DIR"

echo "=== 1. 目前 ACL ==="
sudo synoacltool -get "$HOME_DIR"

echo "=== 2. 清 ACL + 修 home 權限 ==="
sudo synoacltool -del "$HOME_DIR"
sudo chmod 700 "$HOME_DIR"

echo "=== 3. 確認 git_devs 群組成員還在 ==="
grep git_devs /etc/group

echo "=== 4. 檢查 authorized_keys 位置/內容 ==="
if [ -f "$HOME_DIR/.ssh/authorized_keys" ]; then
    ls -la "$HOME_DIR/.ssh/authorized_keys"
    cat "$HOME_DIR/.ssh/authorized_keys"
else
    echo "‼️ $HOME_DIR/.ssh/authorized_keys 不存在！"
fi

echo "=== 5. 檢查有沒有誤植到根目錄的 /.ssh/authorized_keys ==="
if [ -f /.ssh/authorized_keys ]; then
    echo "‼️ 發現誤植檔案，內容如下，需要手動搬到 $HOME_DIR/.ssh/authorized_keys："
    cat /.ssh/authorized_keys
fi

echo "=== 6. 修完後再看一次 ACL，應該是空的 ==="
sudo synoacltool -get "$HOME_DIR"

<#
把這台電腦的 git commit 身分統一成指定名字（例如家用機用 kuoterry）：
  1) 設定 global user.name
  2) 掃描指定的 repo 根目錄，找出「自己另外設了 local user.name/user.email」的 repo
     （local 設定會蓋掉 global，不清掉的話 global 改了也沒用）
  3) 預設只列出、不動；加 -Unset 才會真的清掉 local 覆蓋

用法：
  .\sync-git-identity.ps1 -Name "kuoterry"                      # 只掃描+列出，不改動任何 repo
  .\sync-git-identity.ps1 -Name "kuoterry" -Unset                # 掃描+實際清掉 local 覆蓋
  .\sync-git-identity.ps1 -Name "kuoterry" -Roots "D:\git","E:\projects" -Unset   # 自訂要掃描的根目錄
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string[]]$Roots = @("D:\git", "D:\GIT"),
    [switch]$Unset
)

Write-Host "=== 1) 設定 global user.name ==="
git config --global user.name "$Name"
git config --global --list --show-origin | Select-String "user\."

Write-Host "`n=== 2) 掃描 repo，找 local user.name/user.email 覆蓋 ==="
$found = @()

foreach ($root in $Roots) {
    if (-not (Test-Path $root)) {
        Write-Host "（跳過，路徑不存在：$root）"
        continue
    }
    Get-ChildItem -Path $root -Directory -Filter ".git" -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            $repoPath = $_.Parent.FullName
            Push-Location $repoPath
            $localName = git config --local --get user.name 2>$null
            $localEmail = git config --local --get user.email 2>$null
            if ($localName -or $localEmail) {
                $found += [PSCustomObject]@{ Repo = $repoPath; Name = $localName; Email = $localEmail }
                Write-Host "‼️  $repoPath -> local user.name=$localName user.email=$localEmail"
                if ($Unset) {
                    if ($localName)  { git config --local --unset user.name }
                    if ($localEmail) { git config --local --unset user.email }
                    Write-Host "    -> 已清掉 local 覆蓋，改吃 global"
                }
            }
            Pop-Location
        }
}

Write-Host ""
if ($found.Count -eq 0) {
    Write-Host "沒有 repo 設 local 覆蓋，global 設定（$Name）已經對所有掃到的 repo 生效。"
} elseif (-not $Unset) {
    Write-Host "找到 $($found.Count) 個 repo 有 local 覆蓋，上面只列出、沒有動。加 -Unset 參數重跑會實際清掉。"
} else {
    Write-Host "已清掉 $($found.Count) 個 repo 的 local 覆蓋。"
}

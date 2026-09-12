<#
.SYNOPSIS
  掃描 D:\git 工作區，產出資產盤點用的機械式總表（TSV + Markdown）。

.DESCRIPTION
  對根目錄每個項目（資料夾／檔案）與巢狀 repo（最深 5 層）各產一列：
  名稱、類型、大小、是否 git、最後 commit（author date）、分支、遠端、未提交、未推送(ahead/behind)、最後修改。
  設計成可重跑：每期盤點重跑一次，與上一期 TSV diff 即可抓出新增／移除／活躍度變化。
  不改任何 repo 狀態（只讀 git 命令、不 fetch）。

.PARAMETER Root
  工作區根目錄，預設 D:\git。

.PARAMETER OutDir
  輸出目錄，預設 D:\tmp。產出 scan_workspace_YYYY-MM-DD.tsv 與 .md。

.EXAMPLE
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\scan_workspace.ps1
#>
param(
  [string]$Root = "D:\git",
  [string]$OutDir = "D:\tmp"
)

$ErrorActionPreference = "SilentlyContinue"
$stamp = Get-Date -Format "yyyy-MM-dd"
$tsvPath = Join-Path $OutDir "scan_workspace_$stamp.tsv"
$mdPath  = Join-Path $OutDir "scan_workspace_$stamp.md"

function Get-SizeText([long]$bytes)
{
  if ($bytes -ge 1GB) { return ("{0:N1}G" -f ($bytes / 1GB)) }
  if ($bytes -ge 1MB) { return ("{0:N0}M" -f ($bytes / 1MB)) }
  return ("{0:N0}K" -f [math]::Max(1, $bytes / 1KB))
}

function Get-DirSize([string]$path)
{
  $sum = (Get-ChildItem -LiteralPath $path -Recurse -Force -File | Measure-Object -Property Length -Sum).Sum
  if ($null -eq $sum) { return 0 }
  return [long]$sum
}

function Get-RemoteTag([string]$url)
{
  if ([string]::IsNullOrWhiteSpace($url)) { return "—" }
  if ($url -match "github\.com") { return "GitHub" }
  if ($url -match "Git_Server|synology|192\.168\.")
  {
    if ($url -match "^(?:ssh://)?([^@]+)@" -and $Matches[1] -ne "kuoterry") { return "NAS($($Matches[1]))" }
    return "NAS"
  }
  return "other"
}

function Get-RepoRow([string]$name, [string]$path, [string]$type, [long]$size, [datetime]$mtime)
{
  $isGit = (Test-Path -LiteralPath (Join-Path $path ".git"))
  $row = [ordered]@{
    名稱 = $name; 類型 = $type; 大小 = (Get-SizeText $size)
    Git = ""; 最後commit = "—"; 分支 = "—"; 遠端 = "—"; 未提交 = ""; 未推送 = "—"
    最後修改 = $mtime.ToString("yyyy-MM-dd")
  }
  if ($type -eq "dir") { $row.Git = "✗" }
  if ($isGit)
  {
    $row.Git = "✓"
    $row.最後commit = (& git -C $path log -1 --format=%as 2>$null)
    if (-not $row.最後commit) { $row.最後commit = "(無commit)" }
    $row.分支 = (& git -C $path rev-parse --abbrev-ref HEAD 2>$null)
    if ($row.分支 -eq "HEAD") { $row.分支 = "detached" }
    $row.遠端 = Get-RemoteTag (& git -C $path remote get-url origin 2>$null)
    $dirty = & git -C $path status --porcelain --untracked-files=no 2>$null
    if ($dirty) { $row.未提交 = "Y" } else { $row.未提交 = "N" }
    $ab = & git -C $path rev-list --left-right --count "HEAD...@{u}" 2>$null
    if ($ab)
    {
      $parts = $ab -split "\s+"
      $row.未推送 = "+$($parts[0])/-$($parts[1])"
    }
  }
  return [pscustomobject]$row
}

$rows = @()

# 第一層：根目錄每個項目
foreach ($item in (Get-ChildItem -LiteralPath $Root -Force | Where-Object { $_.Name -ne ".claude" }))
{
  if ($item.PSIsContainer)
  {
    $rows += Get-RepoRow $item.Name $item.FullName "dir" (Get-DirSize $item.FullName) $item.LastWriteTime
  }
  else
  {
    $rows += Get-RepoRow $item.Name $item.FullName "file" $item.Length $item.LastWriteTime
  }
}

# 巢狀 repo：第 2～5 層，遇到 .git 就停止往下（不進 .git、node_modules）
function Find-NestedRepos([string]$dir, [int]$depth)
{
  if ($depth -gt 5) { return }
  foreach ($sub in (Get-ChildItem -LiteralPath $dir -Directory -Force))
  {
    if ($sub.Name -in @(".git", "node_modules", ".venv", "venv", "__pycache__")) { continue }
    if (Test-Path -LiteralPath (Join-Path $sub.FullName ".git"))
    {
      $rel = $sub.FullName.Substring($Root.Length + 1)
      $script:rows += Get-RepoRow $rel $sub.FullName "nested" (Get-DirSize $sub.FullName) $sub.LastWriteTime
      continue
    }
    Find-NestedRepos $sub.FullName ($depth + 1)
  }
}
foreach ($top in (Get-ChildItem -LiteralPath $Root -Directory -Force | Where-Object { $_.Name -ne ".claude" }))
{
  Find-NestedRepos $top.FullName 2
}

$rows = $rows | Sort-Object 名稱
$rows | Export-Csv -LiteralPath $tsvPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8

$md = @("| 名稱 | 類型 | 大小 | Git | 最後commit | 分支 | 遠端 | 未提交 | 未推送 | 最後修改 |", "|---|---|---|---|---|---|---|---|---|---|")
foreach ($r in $rows)
{
  $md += "| $($r.名稱) | $($r.類型) | $($r.大小) | $($r.Git) | $($r.最後commit) | $($r.分支) | $($r.遠端) | $($r.未提交) | $($r.未推送) | $($r.最後修改) |"
}
$md | Out-File -LiteralPath $mdPath -Encoding utf8
Write-Output "rows=$($rows.Count)"
Write-Output "tsv=$tsvPath"
Write-Output "md=$mdPath"

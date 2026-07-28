<#
.SYNOPSIS
  Register a Windows Scheduled Task for Sync-NvdCveDb.ps1.
#>

[CmdletBinding()]
param(
    [string]$ScriptPath = "$PSScriptRoot\Sync-NvdCveDb.ps1",
    [string]$DataDir = "$PSScriptRoot\nvd-data",
    [string]$TaskName = 'NVD CVE DB Daily Sync',
    [string]$Time = '03:20',
    [switch]$BuildCombined,
    # 기본은 현재 사용자 권한(최소 권한). 관리자 권한 실행이 꼭 필요할 때만 -Elevated 로 opt-in.
    # (상승 권한 + 사용자 쓰기 가능 폴더 스크립트 = 로컬 권한 상승 표면이므로 기본에서 배제)
    [switch]$Elevated
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ScriptPath)) {
    throw "Script not found: $ScriptPath"
}

$resolvedScript = (Resolve-Path $ScriptPath).Path
$resolvedDataDir = $DataDir
New-Item -ItemType Directory -Force -Path $resolvedDataDir | Out-Null

$argList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', "`"$resolvedScript`"",
    '-Mode', 'Auto',
    '-DataDir', "`"$resolvedDataDir`""
)

if ($BuildCombined) {
    $argList += '-BuildCombined'
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($argList -join ' ')
$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($Time, 'HH:mm', $null))
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 6) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 10)

if ($Elevated) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
} else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
}

Write-Host "Registered scheduled task: $TaskName"
Write-Host "Script: $resolvedScript"
Write-Host "DataDir: $resolvedDataDir"
Write-Host "Daily time: $Time"
Write-Host ("Privilege : {0}" -f ($(if ($Elevated) { 'Highest (elevated) — 스크립트 폴더 ACL 보호 권장' } else { '현재 사용자(최소 권한)' })))
Write-Host "Run now: Start-ScheduledTask -TaskName '$TaskName'"

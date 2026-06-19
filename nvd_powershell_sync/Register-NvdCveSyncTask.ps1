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
    [switch]$RunAsCurrentUser
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

if ($RunAsCurrentUser) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
} else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
}

Write-Host "Registered scheduled task: $TaskName"
Write-Host "Script: $resolvedScript"
Write-Host "DataDir: $resolvedDataDir"
Write-Host "Daily time: $Time"
Write-Host "Run now: Start-ScheduledTask -TaskName '$TaskName'"

<#
.SYNOPSIS
  Sync local NVD CVE 2.0 JSON database on Windows.

.DESCRIPTION
  - First run: downloads full yearly NVD CVE 2.0 JSON feeds from 2002 to current year.
  - Later runs: downloads nvdcve-2.0-modified.json.gz only when its .meta SHA256 changes.
  - Incremental changes are UPSERTed into local yearly JSON feed files.
  - Optional combined JSON/JSON.GZ export can be generated after sync.

.NOTES
  Requires: Windows PowerShell 5.1+ or PowerShell 7+
  No external modules required.
#>

[CmdletBinding()]
param(
    [ValidateSet('Auto','Full','Incremental','RebuildCombined')]
    [string]$Mode = 'Auto',

    [string]$DataDir = "$PSScriptRoot\nvd-data",

    [int]$StartYear = 2002,

    [int]$EndYear = (Get-Date).Year,

    [switch]$BuildCombined,

    [switch]$NoGzipCombined,

    [int]$MaxStaleDays = 7,

    [int]$RetryCount = 3,

    [int]$RetryDelaySeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BaseUrl = 'https://nvd.nist.gov/feeds/json/cve/2.0'
$StatePath = Join-Path $DataDir 'sync-state.json'
$FeedDir = Join-Path $DataDir 'feeds'
$YearDir = Join-Path $DataDir 'yearly-local'
$MetaDir = Join-Path $DataDir 'meta'
$LogDir = Join-Path $DataDir 'logs'
$TempDir = Join-Path $DataDir 'tmp'
$CombinedDir = Join-Path $DataDir 'combined'

foreach ($dir in @($DataDir, $FeedDir, $YearDir, $MetaDir, $LogDir, $TempDir, $CombinedDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$LogPath = Join-Path $LogDir ("sync-{0}.log" -f (Get-Date -Format 'yyyyMMdd'))

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

function Read-State {
    if (Test-Path $StatePath) {
        return Get-Content -Path $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    return [pscustomobject]@{
        schemaVersion = 1
        fullCompleted = $false
        lastFullSyncUtc = $null
        lastIncrementalSyncUtc = $null
        lastModifiedFeedSha256 = $null
        startYear = $StartYear
        endYear = $EndYear
        yearlySha256 = @{}
    }
}

function Save-State {
    param([object]$State)
    $json = $State | ConvertTo-Json -Depth 100
    Set-Content -Path $StatePath -Value $json -Encoding UTF8
}

function Invoke-DownloadWithRetry {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$OutFile
    )

    for ($i = 1; $i -le $RetryCount; $i++) {
        try {
            Write-Log "Downloading $Uri"
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
            return
        } catch {
            if ($i -eq $RetryCount) { throw }
            Write-Log "Download failed attempt $i/$RetryCount: $($_.Exception.Message). Retrying in $RetryDelaySeconds sec" 'WARN'
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Read-NvdMeta {
    param([Parameter(Mandatory=$true)][string]$Path)

    $result = @{}
    foreach ($line in Get-Content -Path $Path -Encoding ASCII) {
        if ($line -match '^([^:]+):(.*)$') {
            $result[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    return $result
}

function Get-FileSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToUpperInvariant()
}

function Get-GzipUncompressedSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $gz = New-Object System.IO.Compression.GzipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $buffer = New-Object byte[] 1048576
            while (($read = $gz.Read($buffer, 0, $buffer.Length)) -gt 0) {
                [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
            }
            [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
            return (($sha.Hash | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
        } finally {
            $gz.Dispose()
        }
    } finally {
        $fs.Dispose()
        $sha.Dispose()
    }
}

function Assert-NvdGzipSha256 {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256
    )

    # NVD .meta sha256 is the SHA256 of the uncompressed JSON payload, not the .gz container.
    $actual = Get-GzipUncompressedSha256 -Path $Path
    $expected = $ExpectedSha256.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "NVD uncompressed SHA256 mismatch for $Path. expected=$expected actual=$actual"
    }
}

function Read-GzipJson {
    param([Parameter(Mandatory=$true)][string]$Path)

    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $gz = New-Object System.IO.Compression.GzipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $sr = New-Object System.IO.StreamReader($gz, [System.Text.Encoding]::UTF8)
            try {
                $text = $sr.ReadToEnd()
                return $text | ConvertFrom-Json
            } finally {
                $sr.Dispose()
            }
        } finally {
            $gz.Dispose()
        }
    } finally {
        $fs.Dispose()
    }
}

function Write-GzipText {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Text
    )

    $tmp = "$Path.tmp"
    $fs = [System.IO.File]::Create($tmp)
    try {
        $gz = New-Object System.IO.Compression.GzipStream($fs, [System.IO.Compression.CompressionLevel]::Optimal)
        try {
            $sw = New-Object System.IO.StreamWriter($gz, [System.Text.Encoding]::UTF8)
            try {
                $sw.Write($Text)
            } finally {
                $sw.Dispose()
            }
        } finally {
            $gz.Dispose()
        }
    } finally {
        $fs.Dispose()
    }

    Move-Item -Force -Path $tmp -Destination $Path
}

function Save-NvdJsonGzip {
    param(
        [Parameter(Mandatory=$true)][object]$JsonObject,
        [Parameter(Mandatory=$true)][string]$Path
    )

    $text = $JsonObject | ConvertTo-Json -Depth 100 -Compress
    Write-GzipText -Path $Path -Text $text
}

function Get-CveYear {
    param([Parameter(Mandatory=$true)][string]$CveId)
    if ($CveId -notmatch '^CVE-(\d{4})-') {
        throw "Invalid CVE ID: $CveId"
    }
    return [int]$matches[1]
}

function Download-FeedIfNeeded {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [switch]$Force
    )

    $metaUrl = "$BaseUrl/$Name.meta"
    $jsonUrl = "$BaseUrl/$Name.json.gz"
    $metaPath = Join-Path $MetaDir "$Name.meta"
    $gzPath = Join-Path $FeedDir "$Name.json.gz"

    $tmpMeta = Join-Path $TempDir "$Name.meta.tmp"
    Invoke-DownloadWithRetry -Uri $metaUrl -OutFile $tmpMeta
    $meta = Read-NvdMeta -Path $tmpMeta

    if (-not $meta.ContainsKey('sha256')) {
        throw "NVD meta file has no sha256: $metaUrl"
    }

    $remoteSha = $meta['sha256'].ToUpperInvariant()
    $needDownload = $Force -or (-not (Test-Path $gzPath))

    if ((-not $needDownload) -and (Test-Path $metaPath)) {
        $oldMeta = Read-NvdMeta -Path $metaPath
        if (-not $oldMeta.ContainsKey('sha256') -or $oldMeta['sha256'].ToUpperInvariant() -ne $remoteSha) {
            $needDownload = $true
        }
    } elseif (-not (Test-Path $metaPath)) {
        $needDownload = $true
    }

    if ($needDownload) {
        $tmpGz = Join-Path $TempDir "$Name.json.gz.tmp"
        # NVD 는 피드를 주기적으로 갱신한다. .meta 와 .json.gz 를 받는 사이 피드가 갱신되면
        # 해시가 어긋날 수 있으므로, 불일치 시 meta+gz 를 한 번 더 받아 재검증한다(중간 실패 흔한 원인).
        $shaAttempts = 2
        for ($a = 1; $a -le $shaAttempts; $a++) {
            Invoke-DownloadWithRetry -Uri $jsonUrl -OutFile $tmpGz
            try {
                Assert-NvdGzipSha256 -Path $tmpGz -ExpectedSha256 $remoteSha
                break
            } catch {
                if ($a -eq $shaAttempts) { throw }
                Write-Log "SHA mismatch for $Name (feed likely updated mid-fetch). Refreshing meta and retrying." 'WARN'
                Invoke-DownloadWithRetry -Uri $metaUrl -OutFile $tmpMeta
                $meta = Read-NvdMeta -Path $tmpMeta
                if (-not $meta.ContainsKey('sha256')) { throw "NVD meta file has no sha256: $metaUrl" }
                $remoteSha = $meta['sha256'].ToUpperInvariant()
            }
        }
        Move-Item -Force -Path $tmpGz -Destination $gzPath
        Move-Item -Force -Path $tmpMeta -Destination $metaPath
        Write-Log "Updated feed $Name sha256=$remoteSha"
        return [pscustomobject]@{ Updated = $true; Path = $gzPath; Sha256 = $remoteSha; Meta = $meta }
    }

    Remove-Item -Force -Path $tmpMeta -ErrorAction SilentlyContinue
    Write-Log "Feed unchanged $Name sha256=$remoteSha"
    return [pscustomobject]@{ Updated = $false; Path = $gzPath; Sha256 = $remoteSha; Meta = $meta }
}

function Copy-CanonicalYearFeed {
    param(
        [Parameter(Mandatory=$true)][int]$Year,
        [Parameter(Mandatory=$true)][string]$SourceGz
    )

    $dest = Join-Path $YearDir ("nvdcve-2.0-{0}.local.json.gz" -f $Year)
    Copy-Item -Force -Path $SourceGz -Destination $dest
    return $dest
}

function Invoke-FullSync {
    $state = Read-State
    Write-Log "Starting FULL sync: years $StartYear..$EndYear"

    # 기존 진행분을 보존(부분 실패 후 재개). pscustomobject/hashtable 양쪽을 hashtable 로 정규화.
    $yearlySha = @{}
    if ($state.yearlySha256) {
        if ($state.yearlySha256 -is [hashtable]) {
            foreach ($k in $state.yearlySha256.Keys) { $yearlySha[[string]$k] = $state.yearlySha256[$k] }
        } else {
            foreach ($p in $state.yearlySha256.PSObject.Properties) { $yearlySha[$p.Name] = $p.Value }
        }
    }
    $failedYears = New-Object System.Collections.ArrayList

    for ($year = $StartYear; $year -le $EndYear; $year++) {
        $name = "nvdcve-2.0-$year"
        try {
            # -Force 제거: 변동 없는 해(저장된 .meta sha 동일)는 건너뛰어 재실행이 곧 '재개'가 된다.
            $feed = Download-FeedIfNeeded -Name $name
            $localPath = Copy-CanonicalYearFeed -Year $year -SourceGz $feed.Path
            $yearlySha["$year"] = Get-FileSha256 -Path $localPath
            # 연도별로 즉시 상태 저장 → 중간에 죽어도 진행분이 남고 다음 실행이 이어서 받는다.
            $state.yearlySha256 = $yearlySha
            $state.startYear = $StartYear
            $state.endYear = $EndYear
            Save-State -State $state
            Write-Log "Stored local yearly feed year=$year path=$localPath"
        } catch {
            [void]$failedYears.Add($year)
            Write-Log "Year $year failed: $($_.Exception.Message). Continuing with remaining years." 'WARN'
        }
    }

    $state.startYear = $StartYear
    $state.endYear = $EndYear
    $state.yearlySha256 = $yearlySha

    if ($failedYears.Count -gt 0) {
        # 한 해라도 실패하면 fullCompleted 를 false 로 유지 → Auto 모드가 다음에 다시 Full 로 빠진 해만 마저 받는다.
        $state.fullCompleted = $false
        Save-State -State $state
        Write-Log ("FULL sync incomplete. Failed years: {0}. Re-run (-Mode Full or Auto) to retry only the missing/changed years." -f ($failedYears -join ', ')) 'WARN'
        return
    }

    $state.fullCompleted = $true
    $state.lastFullSyncUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state.lastIncrementalSyncUtc = $null
    Save-State -State $state

    if ($BuildCombined) {
        Invoke-RebuildCombined -NoGzip:$NoGzipCombined
    }

    Write-Log 'FULL sync completed'
}

function Invoke-IncrementalSync {
    $state = Read-State
    if (-not $state.fullCompleted) {
        throw 'Full sync has not completed. Run -Mode Full first, or use -Mode Auto.'
    }

    if ($state.lastIncrementalSyncUtc) {
        $last = [datetime]::Parse($state.lastIncrementalSyncUtc).ToUniversalTime()
    } elseif ($state.lastFullSyncUtc) {
        $last = [datetime]::Parse($state.lastFullSyncUtc).ToUniversalTime()
    } else {
        $last = (Get-Date).ToUniversalTime().AddDays(-9999)
    }

    $ageDays = ((Get-Date).ToUniversalTime() - $last).TotalDays
    if ($ageDays -gt $MaxStaleDays) {
        throw "Local DB is stale for $([math]::Round($ageDays, 1)) days. NVD modified feed is intended for recent changes. Run -Mode Full, or increase -MaxStaleDays deliberately."
    }

    Write-Log 'Starting INCREMENTAL sync from modified feed'
    $feed = Download-FeedIfNeeded -Name 'nvdcve-2.0-modified'

    if (-not $feed.Updated -and $state.lastModifiedFeedSha256 -eq $feed.Sha256) {
        Write-Log 'Modified feed unchanged. Nothing to apply.'
        $state.lastIncrementalSyncUtc = (Get-Date).ToUniversalTime().ToString('o')
        Save-State -State $state
        return
    }

    $modified = Read-GzipJson -Path $feed.Path
    $items = @($modified.vulnerabilities)
    Write-Log "Modified feed contains $($items.Count) vulnerability records"

    $byYear = @{}
    foreach ($item in $items) {
        $cveId = [string]$item.cve.id
        $year = Get-CveYear -CveId $cveId
        if (-not $byYear.ContainsKey($year)) {
            $byYear[$year] = New-Object System.Collections.ArrayList
        }
        [void]$byYear[$year].Add($item)
    }

    $totalApplied = 0
    foreach ($year in ($byYear.Keys | Sort-Object)) {
        $localPath = Join-Path $YearDir ("nvdcve-2.0-{0}.local.json.gz" -f $year)
        if (-not (Test-Path $localPath)) {
            Write-Log "Local yearly feed for $year is missing. Downloading original year feed first." 'WARN'
            $yearFeed = Download-FeedIfNeeded -Name "nvdcve-2.0-$year" -Force
            Copy-CanonicalYearFeed -Year $year -SourceGz $yearFeed.Path | Out-Null
        }

        Write-Log "Applying $($byYear[$year].Count) records to year=$year"
        $yearJson = Read-GzipJson -Path $localPath
        $map = @{}

        foreach ($v in @($yearJson.vulnerabilities)) {
            $map[[string]$v.cve.id] = $v
        }

        foreach ($v in $byYear[$year]) {
            $map[[string]$v.cve.id] = $v
            $totalApplied++
        }

        $updatedList = @($map.Values | Sort-Object { [string]$_.cve.id })
        $yearJson.vulnerabilities = $updatedList
        if ($yearJson.PSObject.Properties.Name -contains 'totalResults') {
            $yearJson.totalResults = $updatedList.Count
        }
        if ($yearJson.PSObject.Properties.Name -contains 'resultsPerPage') {
            $yearJson.resultsPerPage = $updatedList.Count
        }
        if ($yearJson.PSObject.Properties.Name -contains 'timestamp') {
            $yearJson.timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff')
        }

        Save-NvdJsonGzip -JsonObject $yearJson -Path $localPath
        Write-Log "Updated local yearly feed year=$year total=$($updatedList.Count)"
    }

    $state.lastIncrementalSyncUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state.lastModifiedFeedSha256 = $feed.Sha256
    Save-State -State $state

    if ($BuildCombined) {
        Invoke-RebuildCombined -NoGzip:$NoGzipCombined
    }

    Write-Log "INCREMENTAL sync completed applied=$totalApplied"
}

function Invoke-RebuildCombined {
    param([switch]$NoGzip)

    Write-Log 'Rebuilding combined CVE DB'
    $outName = if ($NoGzip) { 'nvd-cve-2.0-combined.json' } else { 'nvd-cve-2.0-combined.json.gz' }
    $outPath = Join-Path $CombinedDir $outName
    $tmpPath = "$outPath.tmp"

    if ($NoGzip) {
        $fs = [System.IO.File]::Create($tmpPath)
    } else {
        $fsRaw = [System.IO.File]::Create($tmpPath)
        $fs = New-Object System.IO.Compression.GzipStream($fsRaw, [System.IO.Compression.CompressionLevel]::Optimal)
    }

    try {
        $sw = New-Object System.IO.StreamWriter($fs, [System.Text.Encoding]::UTF8)
        try {
            $sw.Write('{"format":"NVD_CVE","version":"2.0","generatedAt":"')
            $sw.Write((Get-Date).ToUniversalTime().ToString('o'))
            $sw.Write('","vulnerabilities":[')

            $first = $true
            $total = 0
            for ($year = $StartYear; $year -le $EndYear; $year++) {
                $localPath = Join-Path $YearDir ("nvdcve-2.0-{0}.local.json.gz" -f $year)
                if (-not (Test-Path $localPath)) { continue }

                $yearJson = Read-GzipJson -Path $localPath
                foreach ($item in @($yearJson.vulnerabilities)) {
                    if (-not $first) { $sw.Write(',') }
                    $sw.Write(($item | ConvertTo-Json -Depth 100 -Compress))
                    $first = $false
                    $total++
                }
            }

            $sw.Write('],"totalResults":')
            $sw.Write($total)
            $sw.Write('}')
        } finally {
            $sw.Dispose()
        }
    } finally {
        if (-not $NoGzip) {
            $fs.Dispose()
            $fsRaw.Dispose()
        } else {
            $fs.Dispose()
        }
    }

    Move-Item -Force -Path $tmpPath -Destination $outPath
    Write-Log "Combined CVE DB written: $outPath"
}

try {
    Write-Log "NVD CVE sync started mode=$Mode dataDir=$DataDir"

    switch ($Mode) {
        'Full' { Invoke-FullSync }
        'Incremental' { Invoke-IncrementalSync }
        'RebuildCombined' { Invoke-RebuildCombined -NoGzip:$NoGzipCombined }
        'Auto' {
            $state = Read-State
            if (-not $state.fullCompleted) {
                Write-Log 'Auto mode selected FULL sync because local DB has no completed full sync state'
                Invoke-FullSync
            } else {
                Write-Log 'Auto mode selected INCREMENTAL sync'
                Invoke-IncrementalSync
            }
        }
    }

    Write-Log 'NVD CVE sync finished successfully'
    exit 0
} catch {
    Write-Log "FAILED: $($_.Exception.Message)" 'ERROR'
    Write-Log $_.ScriptStackTrace 'ERROR'
    exit 1
}

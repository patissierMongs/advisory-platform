<#
.SYNOPSIS
  내부망 포트 식별 스캐너 (독립 실행형). 콘솔 의존 없음 — 이 폴더만 스캔 서버로 복사해 사용.

.DESCRIPTION
  목적: 열린 포트를 찾고 "무슨 서비스/프로그램/역할"인지 식별해 관리자에게 근거와 함께 전달.
  산출물 정본 = nmap XML (무손실). 회차 폴더(out\<타임스탬프>\) 통째로 콘솔에 투입·아카이브.
  콘솔이 XML 을 파싱해 표시/CSV export/diff 를 담당. (도구는 "스캔해서 XML 떨군다"에 집중)
  파이프라인(6단계):
    0) 준비   : 대상 목록(targets\hosts.txt) + 프리셋 선택
    1) 디스커버리 : 생존 호스트 발굴(L3 → IP 프로브)              → 1_discovery.xml
    2) 포트맵 : TCP 전체 + UDP 선별, 상태만(버전/스크립트 없음)   → 2_ports_*.xml
    3) 식별   : 열린 포트에만 -sV + 식별 NSE(banner 포함, 호스트별, 취약 포트 제외) → 3_ident\*.xml
    4) 미식별 : (옵션 -DeepBanner) 정체불명 포트만 ncat 보조 배너 → 4_unknown\*.txt
    5) 부가   : (옵션 -Csv) report.csv / 로컬 편의 diff.txt
  안전: -O 없음, --version-all 없음, 취약 포트 능동프로브 제외, 속도 캡(프리셋).

.PARAMETER Preset
  biz(업무망, T4) 또는 inet(인터넷망, T2). presets\<name>.psd1 로드.

.PARAMETER Targets
  대상 파일 경로(IP/CIDR/호스트, 한 줄에 하나). 기본 .\targets\hosts.txt

.EXAMPLE
  .\scan.ps1 -Preset biz                          # XML 정본만 생성(콘솔 투입용)
  .\scan.ps1 -Preset biz -Csv                     # 사람 배포용 CSV 도 함께
  .\scan.ps1 -Preset inet -Targets .\targets\dmz.txt -DeepBanner
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('biz','inet')][string]$Preset,
    [string]$Targets = (Join-Path $PSScriptRoot 'targets\hosts.txt'),
    [string]$OutRoot = (Join-Path $PSScriptRoot 'out'),
    # 산출물: nmap XML 이 정본(콘솔 투입·아카이브). 아래는 부가 옵션.
    [switch]$Csv,         # 사람 배포용 report.csv 도 함께 생성(기본 off)
    [switch]$DeepBanner,  # 정체불명 포트에 ncat 수동 배너 보조(기본 off; banner NSE 로 대부분 XML 에 이미 수집)
    [int]$TopPorts = 0    # >0 이면 TCP 전체(-p-) 대신 --top-ports N (빠른 스캔, 인터넷망 등)
)

$ErrorActionPreference = 'Stop'

# ── 도구 경로 자동탐색: Program Files → (x86) → 도구 옆(.\) ────────────────────
function Resolve-Tool([string]$exe) {
    $bases = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    $cands = @()
    foreach ($b in $bases) { $cands += (Join-Path $b "Nmap\$exe") }
    $cands += (Join-Path $PSScriptRoot $exe)
    foreach ($c in $cands) { if (Test-Path $c) { return $c } }
    throw "$exe 를 찾을 수 없습니다. (탐색: $($cands -join ' ; '))  Nmap 설치 또는 도구 폴더에 동봉하세요."
}
$Nmap = Resolve-Tool 'nmap.exe'
$Ncat = Resolve-Tool 'ncat.exe'

# ── 프리셋 + 출력 폴더 ────────────────────────────────────────────────────────
$presetPath = Join-Path $PSScriptRoot "presets\$Preset.psd1"
if (-not (Test-Path $presetPath)) { throw "프리셋 없음: $presetPath" }
$P = Import-PowerShellDataFile -Path $presetPath
if (-not (Test-Path $Targets)) { throw "대상 파일 없음: $Targets (targets\hosts.txt 에 IP/CIDR 입력)" }

$stamp  = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$RunDir = Join-Path $OutRoot $stamp
New-Item -ItemType Directory -Force -Path $RunDir, (Join-Path $RunDir '3_ident'), (Join-Path $RunDir '4_unknown') | Out-Null
$Log = Join-Path $RunDir 'scan.log'

function Write-Log([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    $line | Tee-Object -FilePath $Log -Append
}
function Invoke-Nmap([string[]]$nargs, [string]$label) {
    Write-Log "nmap $label :: $($nargs -join ' ')"
    & $Nmap @nargs 2>&1 | Tee-Object -FilePath $Log -Append | Out-Null
}

# ── nmap XML 파서 → 호스트/포트 객체 ─────────────────────────────────────────
function Get-NmapHosts([string]$xmlPath) {
    if (-not (Test-Path $xmlPath)) { return @() }
    [xml]$x = Get-Content -Raw -Path $xmlPath
    $out = @()
    foreach ($h in @($x.nmaprun.host)) {
        if (-not $h) { continue }
        if ($h.status.state -ne 'up') { continue }
        $ip = (@($h.address) | Where-Object { $_.addrtype -eq 'ipv4' } | Select-Object -First 1).addr
        if (-not $ip) { $ip = (@($h.address) | Select-Object -First 1).addr }
        $hostname = $null
        if ($h.hostnames -and $h.hostnames.hostname) { $hostname = (@($h.hostnames.hostname) | Select-Object -First 1).name }
        $ports = @()
        foreach ($p in @($h.ports.port)) {
            if (-not $p) { continue }
            if ($p.state.state -notmatch 'open') { continue }   # open / open|filtered
            $scripts = @()
            foreach ($s in @($p.script)) { if ($s) { $scripts += [pscustomobject]@{ Id = $s.id; Output = $s.output } } }
            $ports += [pscustomobject]@{
                Proto     = $p.protocol
                Port      = [int]$p.portid
                State     = $p.state.state
                Reason    = $p.state.reason
                Service   = $p.service.name
                Product   = $p.service.product
                Version   = $p.service.version
                ExtraInfo = $p.service.extrainfo
                Tunnel    = $p.service.tunnel
                Scripts   = $scripts
            }
        }
        $out += [pscustomobject]@{ Ip = $ip; Hostname = $hostname; Ports = $ports }
    }
    return $out
}

Write-Log "=== 스캔 시작 : preset=$Preset, targets=$Targets ==="
Write-Log "nmap=$Nmap  ncat=$Ncat  out=$RunDir"

# ── Stage 1 : 디스커버리 ─────────────────────────────────────────────────────
$discXml  = Join-Path $RunDir '1_discovery.xml'
$liveFile = Join-Path $RunDir 'live.txt'
$dnsFlag  = if ($P.ResolveDns) { @() } else { @('-n') }
Invoke-Nmap (@('-sn') + $P.DiscoveryArgs + $dnsFlag + @('-iL', $Targets, '-oX', $discXml)) 'discovery'

$liveHosts = Get-NmapHosts $discXml
if (-not $liveHosts -or $liveHosts.Count -eq 0) { Write-Log "생존 호스트 0 — 종료."; return }
$hostMeta = @{}
foreach ($h in $liveHosts) { $hostMeta[$h.Ip] = $h.Hostname }
$liveHosts.Ip | Set-Content -Path $liveFile -Encoding ascii
Write-Log "생존 호스트: $($liveHosts.Count)"

# ── Stage 2 : 포트맵(상태만, 버전/스크립트 없음) ─────────────────────────────
$tcpXml = Join-Path $RunDir '2_ports_tcp.xml'
$udpXml = Join-Path $RunDir '2_ports_udp.xml'
$tcpPortArg = if ($TopPorts -gt 0) { @('--top-ports', "$TopPorts") } else { @('-p-') }
Invoke-Nmap (@('-sS') + $tcpPortArg + @('-Pn','-n','--open','--reason') + $P.TcpTiming + @('--stats-every','1m','-iL',$liveFile,'-oX',$tcpXml)) 'stage2-tcp'
Invoke-Nmap (@('-sU','-p',$P.UdpPorts,'-Pn','-n','--open','--reason') + $P.UdpTiming + @('--stats-every','1m','-iL',$liveFile,'-oX',$udpXml)) 'stage2-udp'

# 호스트별 열린 포트 취합
$openByHost = @{}   # ip -> @{ tcp=@(...); udp=@(...) }
foreach ($h in (Get-NmapHosts $tcpXml)) {
    if (-not $openByHost.ContainsKey($h.Ip)) { $openByHost[$h.Ip] = @{ tcp = @(); udp = @() } }
    $openByHost[$h.Ip].tcp = @($h.Ports | ForEach-Object { $_.Port })
}
foreach ($h in (Get-NmapHosts $udpXml)) {
    if (-not $openByHost.ContainsKey($h.Ip)) { $openByHost[$h.Ip] = @{ tcp = @(); udp = @() } }
    $openByHost[$h.Ip].udp = @($h.Ports | ForEach-Object { $_.Port })
}
$totalOpen = ($openByHost.Values | ForEach-Object { $_.tcp.Count + $_.udp.Count } | Measure-Object -Sum).Sum
Write-Log "열린 포트 총합(상태 기준): $totalOpen"

# ── Stage 3 : 식별(호스트별, 열린 포트에만, 취약 포트 제외) ──────────────────
$fragile = @($P.FragilePorts)
$identHostsTcp = @{}  # ip -> Get-NmapHosts 결과(포트객체)
$identHostsUdp = @{}
foreach ($ip in $openByHost.Keys) {
    $tcpP = @($openByHost[$ip].tcp | Where-Object { $_ -notin $fragile })
    if ($tcpP.Count -gt 0) {
        $ox = Join-Path $RunDir "3_ident\$ip`_tcp.xml"
        Invoke-Nmap (@('-sS') + $P.TcpVersion + @('-Pn','-n','--reason','--open') + $P.TcpTiming +
            @('--script',$P.TcpScripts,'--script-timeout',$P.ScriptTimeout,'-p',($tcpP -join ','),$ip,'-oX',$ox)) "stage3-tcp $ip"
        $identHostsTcp[$ip] = (Get-NmapHosts $ox | Select-Object -First 1)
    }
    $udpP = @($openByHost[$ip].udp | Where-Object { $_ -notin $fragile })
    if ($udpP.Count -gt 0) {
        $ox = Join-Path $RunDir "3_ident\$ip`_udp.xml"
        Invoke-Nmap (@('-sU') + $P.UdpVersion + @('-Pn','-n','--reason','--open') + $P.UdpTiming +
            @('--script',$P.UdpScripts,'--script-timeout',$P.ScriptTimeout,'-p',($udpP -join ','),$ip,'-oX',$ox)) "stage3-udp $ip"
        $identHostsUdp[$ip] = (Get-NmapHosts $ox | Select-Object -First 1)
    }
}

# ── 식별 결과 → 포트 레코드(병합) ────────────────────────────────────────────
$WebPorts = @(80,81,88,443,591,2082,2087,2095,3000,5000,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443)
$TlsPorts = @(443,465,587,636,993,995,1443,8443,9443,5061)

function Summarize-Scripts($port) {
    $bits = @()
    foreach ($s in @($port.Scripts)) {
        if (-not $s.Output) { continue }
        $o = ($s.Output -replace '\s+', ' ').Trim()
        if ($o.Length -gt 140) { $o = $o.Substring(0,140) + '…' }
        $bits += "$($s.Id)=$o"
    }
    return ($bits -join ' | ')
}

$records = @()
function Add-Record($ip, $proto, $port, $fragileFlag) {
    $svc = $port.Service; $prod = $port.Product; $ver = $port.Version
    $evi = Summarize-Scripts $port
    $note = ''
    $ident = $false
    if ($fragileFlag) {
        $note = '취약 장비 포트 — 능동 프로브 제외(수동 확인 권장)'
    } else {
        if ($prod -or $ver) { $ident = $true }
        elseif ($evi) { $ident = $true }
        if (-not $ident -and ($svc -in @('unknown','tcpwrapped') -or -not $svc)) { $note = '정체불명 — 벤더 확인 필요' }
    }
    $script:records += [pscustomobject]@{
        RunTime    = $stamp
        Host       = $ip
        Hostname   = $hostMeta[$ip]
        Proto      = $proto
        Port       = $port.Port
        State      = $port.State
        Reason     = $port.Reason
        Service    = $svc
        Product    = $prod
        Version    = $ver
        ExtraInfo  = $port.ExtraInfo
        Identified = if ($ident) { 'Y' } else { 'N' }
        Evidence   = $evi
        Banner     = ''
        Note       = $note
    }
}

# 식별 패스에서 잡힌 포트 우선 기록, 누락(취약 등)은 Stage2 상태로 보강
foreach ($ip in $openByHost.Keys) {
    $seenTcp = @(); $seenUdp = @()
    if ($identHostsTcp[$ip]) { foreach ($p in $identHostsTcp[$ip].Ports) { Add-Record $ip 'tcp' $p $false; $seenTcp += $p.Port } }
    if ($identHostsUdp[$ip]) { foreach ($p in $identHostsUdp[$ip].Ports) { Add-Record $ip 'udp' $p $false; $seenUdp += $p.Port } }
    # 취약 포트 등 식별 제외분: 상태만이라도 행 남김
    foreach ($pt in ($openByHost[$ip].tcp | Where-Object { $_ -notin $seenTcp })) {
        Add-Record $ip 'tcp' ([pscustomobject]@{ Port=$pt; State='open'; Reason='(상태만)'; Service=$null; Product=$null; Version=$null; ExtraInfo=$null; Scripts=@() }) ($pt -in $fragile)
    }
    foreach ($pt in ($openByHost[$ip].udp | Where-Object { $_ -notin $seenUdp })) {
        Add-Record $ip 'udp' ([pscustomobject]@{ Port=$pt; State='open|filtered'; Reason='(상태만)'; Service=$null; Product=$null; Version=$null; ExtraInfo=$null; Scripts=@() }) ($pt -in $fragile)
    }
}

# ── Stage 4 : 미식별 포트 ncat 배너 그랩(파이프라인 내, 취약 포트 제외) ──────
function Get-Banner($ip, $port, $useTls) {
    try {
        if ($port -in $WebPorts) {
            $req = "GET / HTTP/1.0`r`nHost: $ip`r`n`r`n"
            if ($useTls) { return ($req | & $Ncat --ssl -w 4 $ip $port 2>$null | Out-String) }
            else         { return ($req | & $Ncat       -w 4 $ip $port 2>$null | Out-String) }
        }
        if ($useTls) { return (& $Ncat --ssl --recv-only -w 4 $ip $port 2>$null | Out-String) }
        return (& $Ncat --recv-only -w 4 $ip $port 2>$null | Out-String)
    } catch { return '' }
}

if ($DeepBanner) {
    foreach ($r in ($records | Where-Object { $_.Identified -eq 'N' -and $_.Note -notlike '취약*' })) {
        $useTls = ($r.Port -in $TlsPorts)
        $b = Get-Banner $r.Host $r.Port $useTls
        if (-not $b -and $r.Port -in $WebPorts) { $b = Get-Banner $r.Host $r.Port (-not $useTls) }  # 반대 방식 한 번 더
        $b = ($b -replace '\x00','').Trim()
        if ($b) {
            Add-Content -Path (Join-Path $RunDir "4_unknown\$($r.Host).txt") -Value ("=== {0}:{1}/{2} ===`r`n{3}`r`n" -f $r.Host,$r.Port,$r.Proto,$b)
            $snip = ($b -replace '\s+', ' ').Trim()
            if ($snip.Length -gt 160) { $snip = $snip.Substring(0,160) + '…' }
            $r.Banner = $snip
            $r.Identified = 'P'   # Partial — 배너 확보, 사람 판독 필요
            $r.Note = '배너 확보 — 판독 필요'
        }
    }
}

# ── Stage 5 : (옵션) report.csv + 직전 회차 대비 diff ────────────────────────
# 정본은 nmap XML. CSV 는 사람 배포가 필요할 때만(-Csv).
if ($Csv) {
    $reportCsv = Join-Path $RunDir 'report.csv'
    $records | Sort-Object Host, Proto, Port | Export-Csv -Path $reportCsv -NoTypeInformation -Encoding UTF8
    Write-Log "CSV(사람 배포용): $reportCsv"
}

# 추적용 열린포트 집합(작은 내부 파일, diff 전용 — 항상 생성)
$openCsv = Join-Path $RunDir 'openports.csv'
$records | Select-Object Host, Proto, Port | Sort-Object Host, Proto, Port | Export-Csv -Path $openCsv -NoTypeInformation -Encoding UTF8

# 직전 회차(이번 폴더 제외 최신) 찾아 diff
$prev = Get-ChildItem -Path $OutRoot -Directory | Where-Object { $_.FullName -ne $RunDir } |
        Sort-Object Name -Descending | Select-Object -First 1
$diffFile = Join-Path $RunDir 'diff.txt'
if ($prev -and (Test-Path (Join-Path $prev.FullName 'openports.csv'))) {
    $cur  = $records | ForEach-Object { "$($_.Host)`t$($_.Proto)`t$($_.Port)" }
    $old  = Import-Csv (Join-Path $prev.FullName 'openports.csv') | ForEach-Object { "$($_.Host)`t$($_.Proto)`t$($_.Port)" }
    $new    = $cur | Where-Object { $_ -notin $old }
    $closed = $old | Where-Object { $_ -notin $cur }
    @(
        "직전 회차: $($prev.Name)",
        "신규 열린 포트(NEW): $($new.Count)",
        ($new    | ForEach-Object { "  + $_" }),
        "닫힌 포트(CLOSED): $($closed.Count)",
        ($closed | ForEach-Object { "  - $_" })
    ) | Set-Content -Path $diffFile -Encoding UTF8
    Write-Log "diff: NEW=$($new.Count) CLOSED=$($closed.Count) (vs $($prev.Name))"
} else {
    "직전 회차 없음 — 최초 스캔(기준선)." | Set-Content -Path $diffFile -Encoding UTF8
}

$unkN = @($records | Where-Object { $_.Identified -ne 'Y' }).Count
Write-Log "=== 완료 : 포트 $($records.Count)건, 미식별/판독필요 ${unkN}건 ==="
Write-Log "정본(XML) 폴더: $RunDir"
Write-Host ""
Write-Host "완료 → $RunDir  (이 폴더(XML)를 콘솔에 투입)" -ForegroundColor Green
Write-Host "  열린 포트 $($records.Count) · 미식별/판독필요 $unkN · diff $diffFile$(if($Csv){' · report.csv'})"

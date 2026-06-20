# 인터넷망(Internet, 망분리·별도 스캔서버) 프리셋 — T3도 못 버틴다 가정 → 초저강도.
# 안전 최우선: T2 유지, 1~2 호스트 직렬, 최소 스크립트. -O 없음, version-all 없음.
@{
    DiscoveryArgs = @('-PE','-PS80,443,22,3389,8080,8443','-PA80','-T2','--max-rate','100')
    ResolveDns    = $false  # 망분리 서버는 DNS 없을 수 있음 → PTR 미사용

    TcpTiming     = @('-T2','--max-rate','200','--scan-delay','20ms','--max-retries','2','--max-hostgroup','2','--host-timeout','45m')
    UdpTiming     = @('-T2','--max-rate','100','--scan-delay','50ms','--max-retries','1','--max-hostgroup','2','--host-timeout','30m')

    TcpVersion    = @('-sV','--version-intensity','3')   # 프로브 수 절감
    UdpVersion    = @('-sV','--version-intensity','0')

    TcpScripts    = 'banner,http-title,http-server-header,ssl-cert'   # 최소 저강도 식별
    UdpScripts    = 'snmp-info,ntp-info,dns-nsid'
    UdpPorts      = '53,123,161,500,1900,5353'

    ScriptTimeout = '20s'

    FragilePorts  = @(623, 502, 47808, 17185, 20000, 44818)
}

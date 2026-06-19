# 업무망(Business) 프리셋 — 천장 T4. "멈추면 안 됨" 원칙 유지.
# 안전장치: -O 없음, --version-all 없음, 취약 포트는 -sV/배너 프로브 제외.
@{
    # 더 밀고 싶으면 --max-rate / --max-hostgroup 숫자만 올리세요(-T/-O/version-all 금지).
    DiscoveryArgs = @('-PE','-PP','-PS22,80,135,443,445,3389','-PA80','-PU161,137','-T4','--max-rate','500')
    ResolveDns    = $true   # 업무망: PTR 호스트명을 식별 단서로 수집

    TcpTiming     = @('-T4','--max-rate','2000','--max-retries','2','--max-hostgroup','32','--host-timeout','30m')
    UdpTiming     = @('-T4','--max-rate','600','--max-retries','2','--max-hostgroup','16','--host-timeout','30m')

    TcpVersion    = @('-sV')                              # 기본 intensity(7)
    UdpVersion    = @('-sV','--version-intensity','3')

    TcpScripts    = 'banner,http-title,http-server-header,http-headers,http-favicon,ssl-cert,ssl-cert-intaddr,ssh-hostkey,nbstat,smb-os-discovery,smb2-security-mode,rdp-ntlm-info,ms-sql-info,oracle-tns-version,mysql-info,ldap-rootdse,snmp-info,rpcinfo,sip-methods,upnp-info'
    UdpScripts    = 'banner,snmp-info,snmp-sysdescr,nbstat,ntp-info,rpcinfo,ike-version,sip-methods,dns-nsid'
    UdpPorts      = '53,67,69,88,111,123,137,138,161,162,389,427,500,514,520,1434,1900,2049,5060,5353,11211'

    ScriptTimeout = '30s'

    # 능동 프로브 시 멈출 수 있는 포트(IPMI/Modbus/BACnet/VxWorks/DNP3/EtherNetIP).
    # Stage 2(포트 상태)에는 잡히되, Stage 3 -sV / Stage 4 배너에서는 제외.
    FragilePorts  = @(623, 502, 47808, 17185, 20000, 44818)
}

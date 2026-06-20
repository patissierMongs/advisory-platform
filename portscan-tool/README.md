# portscan-tool

내부망 **포트 식별 스캐너** (독립 실행형). 열린 포트를 찾고 *"무슨 서비스/프로그램/역할인지"* 를
근거와 함께 식별하는 것이 목적입니다. 관리 콘솔과 분리되어, **이 폴더만 스캔 서버로 복사**해 사용합니다.

## 요구 사항
- Windows + PowerShell 5.1+
- **Nmap**(+동봉 **Ncat**). 도구는 다음 순서로 자동 탐색합니다:
  `C:\Program Files\Nmap` → `C:\Program Files (x86)\Nmap` → 이 폴더(`.\`, 포터블 동봉 시)

## 사용법
```powershell
# 1) 대상 준비
copy .\targets\hosts.example.txt .\targets\hosts.txt
notepad .\targets\hosts.txt        # IP / CIDR / 호스트 입력

# 2) 실행 (프리셋 선택)
.\scan.ps1 -Preset biz             # 업무망(T4)
.\scan.ps1 -Preset inet            # 인터넷망(T2, 초저강도)

# 옵션
.\scan.ps1 -Preset biz -Csv        # 사람 배포용 report.csv 도 생성
.\scan.ps1 -Preset biz -DeepBanner # 정체불명 포트에 ncat 보조 배너
```

## 산출물
실행마다 `out\<타임스탬프>\` 폴더 생성. **정본은 nmap XML** (무손실):
- `1_discovery.xml` — 생존 호스트
- `2_ports_tcp.xml`, `2_ports_udp.xml` — 포트 상태(버전/스크립트 없음)
- `3_ident\<ip>_tcp.xml`, `3_ident\<ip>_udp.xml` — **식별**(`-sV` + NSE, 호스트별)
- `diff.txt` — 직전 회차 대비 신규/폐쇄 포트(로컬 편의)
- (옵션) `report.csv`, `4_unknown\<ip>.txt`

→ 콘솔 투입/아카이브에는 **이 폴더(XML)를 통째로** 넣으세요. 표시·CSV export·정식 diff 는 콘솔이 담당.

## 파이프라인 (6단계)
| 단계 | 내용 |
|---|---|
| 0 준비 | 대상 목록 + 프리셋 |
| 1 디스커버리 | 생존 호스트(L3 → IP 프로브) |
| 2 포트맵 | TCP 전체 + UDP 선별, 상태만 |
| 3 식별 | 열린 포트에만 `-sV` + 식별 NSE(호스트별) |
| 4 미식별 | (옵션) ncat 보조 배너 |
| 5 부가 | (옵션) CSV / 로컬 diff |

## 안전 설계 (운영망 보호)
- `-O`(OS 탐지) **없음**, `--version-all` **없음** — 취약 스택 정지 위험 회피
- 취약 장비 포트(IPMI 623 · Modbus 502 · BACnet 47808 등)는 **능동 프로브 제외**(상태만 보고)
- 속도 캡은 프리셋의 `--max-rate`/`--scan-delay`/`--max-hostgroup` 로 제어
- 더 밀려면 그 숫자만 조정. `-T`/`-O`/`--version-all` 은 건드리지 말 것(정지 트리거)

## 프리셋
| | biz(업무망) | inet(인터넷망) |
|---|---|---|
| 타이밍 | `-T4` | `-T2` |
| 속도 | `--max-rate 2000` | `--max-rate 200` + `--scan-delay 20ms` |
| 동시 호스트 | 32 | 2 |
| 버전 강도 | `-sV`(7) | intensity 3 |
| 스크립트 | 식별 풀세트 | 최소 |

`presets\*.psd1` 수정으로 포트·스크립트·타이밍 조정 가능.

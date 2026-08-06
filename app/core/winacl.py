"""data 폴더 접근 제한 — Windows NTFS ACL (운영 타깃) / POSIX 모드 (개발·CI).

왜 chmod 가 아닌가
    타깃은 Windows amd64 다. Windows 에서 os.chmod 는 read-only 비트만 건드리는
    사실상 no-op 이라, POSIX 0700 을 걸어도 다른 로컬 사용자와 네트워크 공유 접근이
    그대로 열려 있다. 실제 접근 제어는 NTFS ACL 이 한다.

왜 icacls 인가
    Windows 내장 도구(%SystemRoot%\\System32\\icacls.exe)라 새 의존성이 없다.
    폐쇄망 오프라인 설치 경로(vendor\\wheels)를 건드리지 않는다는 제약을 지킨다.

한계 (문서에도 명시)
    운영자 계정으로 start.bat 을 직접 실행하는 구성에서 이 ACL 은 일반 사용자와
    네트워크 공유 접근을 차단한다. 그러나 같은 PC 의 다른 로컬 관리자는 소유권 획득으로
    여전히 열람할 수 있다. 그 이상이 필요하면 전용 저권한 서비스 계정 또는 암호화가 필요하다.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# 잘 알려진 SID 로 지정한다. 한국어 Windows 등 현지화 환경에서 'Administrators' 같은
# 그룹 이름 문자열은 다르거나 콘솔 인코딩에서 깨지지만, SID 는 어디서나 동일하다.
SID_SYSTEM = "*S-1-5-18"
SID_ADMINISTRATORS = "*S-1-5-32-544"

# (OI)(CI)F = 객체/컨테이너 상속 + 모든 권한. 이후 만들어지는 하위 파일·폴더가 자동으로
# 같은 ACL 을 물려받으므로 파일마다 호출할 필요가 없다.
_INHERIT_FULL = "(OI)(CI)F"

SENTINEL_NAME = ".acl_applied"


def current_account() -> str | None:
    """구동 계정을 DOMAIN\\USER 형태로. 판별 불가면 None(그 경우 계정 ACE 를 생략)."""
    user = os.environ.get("USERNAME") or ""
    if not user:
        return None
    domain = os.environ.get("USERDOMAIN") or ""
    return f"{domain}\\{user}" if domain else user


def build_icacls_args(path: Path, account: str | None) -> list[str]:
    """icacls 인자 조립 — 부수효과가 없어 단위 테스트로 검증 가능하게 분리했다.

    /inheritance:r 이 핵심이다. 상속 ACE 를 제거해야 상위 폴더(대개 C:\\ 또는 사용자
    프로필)에서 내려오는 Users 그룹의 기본 읽기 권한이 끊긴다. 이걸 빼면 grant 를
    아무리 걸어도 일반 사용자가 계속 읽을 수 있다.
    """
    grants = [f"{SID_SYSTEM}:{_INHERIT_FULL}", f"{SID_ADMINISTRATORS}:{_INHERIT_FULL}"]
    if account:
        grants.append(f"{account}:{_INHERIT_FULL}")
    return ["icacls", str(path), "/inheritance:r", "/grant:r", *grants, "/T", "/C", "/Q"]


def harden_dir(path: Path, *, force: bool = False) -> bool:
    """디렉터리 접근을 구동 계정·SYSTEM·Administrators 로 제한. 성공 여부 반환.

    실패해도 예외를 올리지 않는다 — ACL 적용 실패로 서버가 안 뜨면 그 자체가 운영 사고다.
    대신 수동 복구 명령을 그대로 출력한다.
    """
    if sys.platform != "win32":
        try:
            path.chmod(0o700)          # 개발 PC·CI 용. 운영 타깃 경로는 아래 icacls.
            return True
        except OSError:
            return False

    sentinel = path / SENTINEL_NAME
    if sentinel.exists() and not force:
        return True                    # 멱등 — 매 기동마다 재적용하지 않는다

    args = build_icacls_args(path, current_account())
    try:
        # shell=False 고정. 경로에 공백·한글이 들어가도 인자 리스트로 안전하게 전달된다.
        proc = subprocess.run(args, shell=False, capture_output=True, timeout=60, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        _warn(path, args, f"icacls 실행 실패: {e}")
        return False

    if proc.returncode != 0:
        _warn(path, args, (proc.stderr or proc.stdout or "").strip())
        return False

    try:
        sentinel.write_text("ok", encoding="utf-8")
    except OSError:
        pass                           # 표식 실패는 다음 기동에 한 번 더 적용될 뿐
    print(f"[acl] data 폴더 접근 제한 적용: {path}", flush=True)
    return True


def _warn(path: Path, args: list[str], detail: str) -> None:
    print(f"[acl] 경고: {path} 접근 제한을 적용하지 못했습니다 — {detail}", flush=True)
    print(f"[acl] 관리자 권한 명령 프롬프트에서 직접 실행하세요:\n  {subprocess.list2cmdline(args)}",
          flush=True)

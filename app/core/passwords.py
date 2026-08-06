"""비밀번호 해싱 — 표준 라이브러리만 사용(폐쇄망 전제, 새 의존성 금지).

저장 포맷은 알고리즘·파라미터를 문자열에 내장한다. 나중에 파라미터를 올려도 기존 해시를
그대로 검증할 수 있고, 로그인 성공 시 조용히 재해시(needs_rehash)해 점진 상향이 가능하다.

    scrypt$n=16384,r=8,p=1$<b64 salt>$<b64 dk>
    pbkdf2$iterations=600000$<b64 salt>$<b64 dk>

기본은 scrypt(메모리 하드)지만, hashlib.scrypt 는 링크된 OpenSSL 빌드에 의존한다.
타깃이 Windows 임베디드 Python(build_allinone.py)이라 가용성을 보장할 수 없어
import 시 1회 probe 후 불가하면 pbkdf2-HMAC-SHA256 으로 자동 전환한다(양쪽 다 검증 가능).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import unicodedata

_SALT_BYTES = 16
_DK_BYTES = 32

# scrypt 파라미터 — n=16384,r=8 은 약 16MB 를 쓴다. OpenSSL 의 기본 maxmem(32MB)이
# 이 요구량에 근접하고 빌드마다 달라, 넉넉한 값을 항상 명시적으로 넘긴다.
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024

_PBKDF2_ITERATIONS = 600_000


def _scrypt_available() -> bool:
    try:
        hashlib.scrypt(b"probe", salt=b"\x00" * _SALT_BYTES, n=_SCRYPT_N, r=_SCRYPT_R,
                       p=_SCRYPT_P, dklen=_DK_BYTES, maxmem=_SCRYPT_MAXMEM)
    except Exception:  # noqa: BLE001 — ValueError/AttributeError/OpenSSL 오류 전부 폴백 대상
        return False
    return True


SCRYPT_OK = _scrypt_available()
DEFAULT_ALG = "scrypt" if SCRYPT_OK else "pbkdf2"


def normalize(password: str) -> bytes:
    """한글 IME 입력 일관성 — 해시·검증 양쪽에서 동일하게 적용해야 한다.

    같은 글자라도 조합형/완성형 코드포인트가 달라질 수 있어, NFKC 로 정규화하지 않으면
    '분명히 맞게 쳤는데 로그인 실패' 가 발생한다.
    """
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _derive(alg: str, params: dict[str, int], password: str, salt: bytes) -> bytes:
    if alg == "scrypt":
        return hashlib.scrypt(normalize(password), salt=salt, n=params["n"], r=params["r"],
                              p=params["p"], dklen=_DK_BYTES, maxmem=_SCRYPT_MAXMEM)
    if alg == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", normalize(password), salt,
                                   params["iterations"], dklen=_DK_BYTES)
    raise ValueError(f"지원하지 않는 해시 알고리즘: {alg}")


def _current_params(alg: str) -> dict[str, int]:
    if alg == "scrypt":
        return {"n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P}
    return {"iterations": _PBKDF2_ITERATIONS}


def _format_params(params: dict[str, int]) -> str:
    return ",".join(f"{k}={v}" for k, v in params.items())


def _parse(stored: str) -> tuple[str, dict[str, int], bytes, bytes]:
    alg, param_text, salt_b64, dk_b64 = stored.split("$", 3)
    params = {}
    for pair in param_text.split(","):
        key, value = pair.split("=", 1)
        params[key] = int(value)
    return alg, params, _b64d(salt_b64), _b64d(dk_b64)


def hash_password(password: str, *, alg: str | None = None) -> str:
    alg = alg or DEFAULT_ALG
    params = _current_params(alg)
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = _derive(alg, params, password, salt)
    return f"{alg}${_format_params(params)}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, stored: str | None) -> bool:
    """검증 실패는 예외가 아니라 False — 깨진 해시 문자열이 500 을 내지 않게 한다."""
    if not stored:
        return False
    try:
        alg, params, salt, expected = _parse(stored)
        candidate = _derive(alg, params, password, salt)
    except Exception:  # noqa: BLE001 — 포맷 오류·미지원 알고리즘 전부 '불일치'로 취급
        return False
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str | None) -> bool:
    """저장된 해시가 현재 기본 알고리즘·파라미터와 다르면 True(로그인 성공 시 재해시)."""
    if not stored:
        return False
    try:
        alg, params, _, _ = _parse(stored)
    except Exception:  # noqa: BLE001
        return True
    return alg != DEFAULT_ALG or params != _current_params(alg)


# 존재하지 않는 사용자에도 동일한 연산량을 태워 타이밍으로 계정 존재 여부를 흘리지 않는다.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

MIN_LENGTH = 10
MAX_LENGTH = 200
_DENYLIST = {
    "password", "passw0rd", "1234567890", "qwertyuiop", "administrator",
    "changeme12", "advisory12", "letmein123", "1q2w3e4r5t",
}


def check_policy(password: str, username: str = "") -> None:
    """정책 위반 시 한글 메시지의 ValueError. 호출부가 400 으로 변환한다."""
    if len(password) < MIN_LENGTH:
        raise ValueError(f"비밀번호는 {MIN_LENGTH}자 이상이어야 합니다.")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"비밀번호는 {MAX_LENGTH}자 이하여야 합니다.")
    if username and password.casefold() == username.casefold():
        raise ValueError("비밀번호를 아이디와 같게 설정할 수 없습니다.")
    if password.casefold() in _DENYLIST:
        raise ValueError("너무 흔한 비밀번호입니다. 다른 값을 사용하세요.")

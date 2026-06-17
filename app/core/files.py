"""업로드 파일명 안전화 — 경로 traversal(임의 파일 쓰기) 차단 (보안).

업로드의 file.filename 은 사용자가 제어한다. 'a/../../evil.txt' 처럼 구분자·상위참조를
담아 보내면 저장 디렉터리(EVIDENCE_DIR/FEED_DIR) 밖에 파일을 쓸 수 있다. 온디스크 경로
조립 전 이 함수로 마지막 기본명만 남긴다. (표시용 원본명은 별도 컬럼에 보존)
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

# 한글/영숫자/._- 와 공백만 허용, 나머지는 _ 로 치환(구분자 제거는 .name 이 1차로 처리).
_UNSAFE = re.compile(r"[^\w.\- ]", re.UNICODE)


def safe_filename(name: str | None, default: str = "file") -> str:
    """디렉터리 성분·구분자를 제거하고 마지막 기본명만 반환.

    'a/../../evil.txt' -> 'evil.txt', 'x\\..\\..\\evil' -> 'evil', '..' -> default.
    """
    base = PurePosixPath((name or "").replace("\\", "/")).name  # 마지막 성분만(경로 탈출 제거)
    base = _UNSAFE.sub("_", base).strip(". ")                    # 위험문자/끝점·공백 제거
    return base or default

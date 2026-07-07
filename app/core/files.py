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


# inline 렌더가 안전한 증빙 확장자 — 그 외(html/svg/js 등)는 첨부 강제로 stored-XSS 차단.
_INLINE_SAFE_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".txt", ".csv", ".log"}


def evidence_response(path: str, display_name: str | None):
    """증빙 파일 응답 — 안전한 타입만 inline, 나머지는 attachment. 항상 nosniff.

    증빙 업로드는 확장자 제한이 없으므로(운영 편의) 임의 HTML 을 사이트 오리진에서
    inline 서빙하면 stored-XSS 벡터가 된다. 표시명은 safe_filename 으로 헤더 안전화.
    """
    from fastapi.responses import FileResponse

    name = safe_filename(display_name, default="evidence")
    ext = PurePosixPath(name.lower()).suffix
    disposition = "inline" if ext in _INLINE_SAFE_EXT else "attachment"
    return FileResponse(path, filename=name, headers={
        "Content-Disposition": f'{disposition}; filename="{name}"',
        "X-Content-Type-Options": "nosniff",
    })

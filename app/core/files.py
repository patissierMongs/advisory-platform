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

# 업로드 허용 확장자 — inline 안전 목록 + 사내에서 실제로 첨부하는 문서 형식.
# disposition 으로 막는 것과 별개로 애초에 저장을 거부한다. .html/.svg/.js/.xhtml 은
# 여기 없으므로 stored-XSS 벡터가 디스크에 남지 않는다.
EVIDENCE_ALLOWED_EXT = _INLINE_SAFE_EXT | {
    ".zip", ".xlsx", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".hwp", ".hwpx",
}

# 확장자별 매직바이트. 클라이언트가 보낸 content_type 은 전적으로 공격자 통제라 쓰지 않는다.
_MAGIC: dict[str, tuple[bytes, ...]] = {
    ".pdf": (b"%PDF",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".bmp": (b"BM",),
    ".webp": (b"RIFF",),
    # OOXML/HWPX 는 zip 컨테이너, 구형 hwp/doc/xls/ppt 는 OLE2 복합문서.
    ".zip": (b"PK\x03\x04", b"PK\x05\x06"),
    ".xlsx": (b"PK\x03\x04",),
    ".docx": (b"PK\x03\x04",),
    ".pptx": (b"PK\x03\x04",),
    ".hwpx": (b"PK\x03\x04",),
    ".hwp": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    ".doc": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    ".xls": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    ".ppt": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
}


def check_evidence_upload(filename: str | None, content: bytes) -> str:
    """증빙 업로드 검증 — 통과 시 안전화된 표시용 파일명 반환, 아니면 HTTPException(415).

    확장자 화이트리스트로 저장 자체를 막고, 매직바이트를 아는 형식은 내용까지 대조한다
    (`evil.png` 안에 HTML 을 넣는 우회 차단).
    """
    from fastapi import HTTPException

    name = safe_filename(filename, default="evidence")
    ext = PurePosixPath(name.lower()).suffix
    if ext not in EVIDENCE_ALLOWED_EXT:
        allowed = ", ".join(sorted(EVIDENCE_ALLOWED_EXT))
        raise HTTPException(415, f"허용되지 않는 파일 형식입니다. 허용: {allowed}")
    magics = _MAGIC.get(ext)
    if magics and not any(content.startswith(m) for m in magics):
        raise HTTPException(415, f"파일 내용이 확장자({ext})와 일치하지 않습니다.")
    return name


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

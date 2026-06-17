"""PDF 페이지 렌더링 + CVE 위치 강조 좌표 (STEP2 원문 뷰어).

pypdfium2(Apache/BSD, 폐쇄망·포터블 안전)로 페이지를 PNG 로 렌더하고, 추출 대상
문자열(CVE 코드)의 화면 좌표 박스를 계산해 프론트가 오버레이로 강조하게 한다.

· PNG 인코딩은 stdlib(zlib)만 사용 — Pillow/numpy 의존성 없음(프로젝트 stdlib 지향).
· pdfium 은 스레드 안전이 아니므로 모듈 락으로 렌더 호출을 직렬화한다.
· 렌더 결과는 data/render/ 에 (파일sha·페이지·배율) 키로 캐시한다.
"""
from __future__ import annotations

import struct
import threading
import zlib
from pathlib import Path

from ..config import DATA_DIR

RENDER_DIR = DATA_DIR / "render"
RENDER_DIR.mkdir(parents=True, exist_ok=True)

_LOCK = threading.Lock()


def _encode_png(buf: bytes, w: int, h: int, stride: int, channels: int) -> bytes:
    """RGB(3) / RGBA(4) 픽셀 버퍼 → PNG 바이트 (stdlib only)."""
    color_type = 6 if channels == 4 else 2  # 6=RGBA, 2=RGB
    row_len = w * channels
    raw = bytearray()
    for y in range(h):
        base = y * stride
        raw.append(0)  # 필터 타입 0(None)
        raw += buf[base:base + row_len]  # stride 패딩 제거
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", w, h, 8, color_type, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 6)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def page_count(pdf_path: str) -> int:
    import pypdfium2 as pdfium

    with _LOCK:
        doc = pdfium.PdfDocument(pdf_path)
        try:
            return len(doc)
        finally:
            doc.close()


def render_page_png(pdf_path: str, page_index: int, scale: float = 2.0) -> bytes:
    """페이지(0-기반)를 PNG 로 렌더. 디스크 캐시 적중 시 즉시 반환."""
    import pypdfium2 as pdfium

    stem = Path(pdf_path).stem
    cache = RENDER_DIR / f"{stem}_p{page_index}_s{scale:g}.png"
    if cache.exists():
        return cache.read_bytes()

    with _LOCK:
        doc = pdfium.PdfDocument(pdf_path)
        try:
            page = doc[page_index]
            bmp = page.render(scale=scale, rev_byteorder=True)  # rev_byteorder → RGB(A) 직접
            png = _encode_png(bytes(bmp.buffer), bmp.width, bmp.height, bmp.stride, bmp.n_channels)
        finally:
            doc.close()
    cache.write_bytes(png)
    return png


def pdf_view(pdf_path: str, terms: list[str], scale: float = 2.0) -> dict:
    """페이지 크기(px)와 강조 대상 문자열들의 화면 박스를 계산.

    반환: {scale, pages:[{index,width,height}], boxes:[{term,page,x,y,w,h}]}.
    좌표는 렌더 PNG 와 동일한 px 기준(원점 좌상단). 스캔본(텍스트 0)은 boxes 빈 배열.
    """
    import pypdfium2 as pdfium

    uniq = list(dict.fromkeys(t for t in terms if t))  # 순서보존 중복제거
    pages: list[dict] = []
    boxes: list[dict] = []
    with _LOCK:
        doc = pdfium.PdfDocument(pdf_path)
        try:
            for pi in range(len(doc)):
                page = doc[pi]
                w_pt, h_pt = page.get_size()
                pages.append({"index": pi, "width": round(w_pt * scale), "height": round(h_pt * scale)})
                if not uniq:
                    continue
                tp = page.get_textpage()
                try:
                    for term in uniq:
                        searcher = tp.search(term, match_case=False, match_whole_word=False)
                        try:
                            m = searcher.get_next()
                            while m:
                                start, count = m
                                for ri in range(tp.count_rects(start, count)):
                                    left, bottom, right, top = tp.get_rect(ri)
                                    boxes.append({
                                        "term": term,
                                        "page": pi,
                                        "x": round(left * scale),
                                        "y": round((h_pt - top) * scale),   # 좌하단원점 → 좌상단원점
                                        "w": round((right - left) * scale),
                                        "h": round((top - bottom) * scale),
                                    })
                                m = searcher.get_next()
                        finally:
                            searcher.close()
                finally:
                    tp.close()
        finally:
            doc.close()
    return {"scale": scale, "pages": pages, "boxes": boxes}

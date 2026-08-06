"""좌표 기반 PDF 표 복원 회귀.

테스트 전략 — 두 갈래로 나눈 이유
    PDF 에 한글을 렌더하려면 CJK 폰트를 임베드해야 하는데, 내장 Helvetica 로는 불가능하고
    폰트 파일을 테스트에 끌어들이면 폐쇄망 원칙(새 자산·의존성 금지)과 충돌한다. 그래서
      · **기하 복원(행 묶기·열 배정·병합셀·표 종료)** 은 ASCII 픽스처 PDF 로 검증하고
      · **한글 헤더 키워드 매칭** 은 PDF 를 거치지 않고 순수 함수에 직접 넣어 검증한다.
    이 분리 때문에 '한글 표가 실제로 복원되는가'는 실물 권고문 PDF 로만 최종 확인할 수 있다.

픽스처 PDF 는 콘텐츠 스트림(`BT /F1 9 Tf 1 0 0 1 x y Tm (text) Tj ET`)을 손으로 조립한다.
app/seed.py 의 _minimal_pdf 는 좌표 배치를 하지 않아 표 테스트에 쓸 수 없어 여기서 따로 만든다.
"""
from __future__ import annotations

import io

import pytest

from app.core import pdf_tables
from app.core.pdf_tables import NO_TABLE, TABLE_OK, TABLE_UNPARSED


def build_pdf(pages: list[list[tuple[float, float, str]]], font_size: int = 9) -> bytes:
    """각 페이지를 [(x, y, text), ...] 로 받아 좌표 배치된 PDF 바이트 생성(ASCII 전용)."""
    page_objs, content_objs = [], []
    for cells in pages:
        parts = [f"BT /F1 {font_size} Tf"]
        for x, y, text in cells:
            esc = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
            parts.append(f"1 0 0 1 {x} {y} Tm ({esc}) Tj")
        parts.append("ET")
        content_objs.append("\n".join(parts).encode("latin-1", "replace"))

    n_pages = len(pages)
    font_id = 3 + n_pages * 2
    objs: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        ("<< /Type /Pages /Kids [" +
         " ".join(f"{3 + i * 2} 0 R" for i in range(n_pages)) +
         f"] /Count {n_pages} >>").encode(),
    ]
    for i, stream in enumerate(content_objs):
        objs.append(
            (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
             f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
             f"/Contents {4 + i * 2} 0 R >>").encode())
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
              % (len(objs) + 1, xref))
    return out.getvalue()


def layout(cols: list[float], header: list[str], body: list[list[str]],
           top: float = 700, pitch: float = 22) -> list[tuple[float, float, str]]:
    """헤더 + 본문을 격자로 배치. 빈 문자열 셀은 아예 그리지 않는다(= 병합셀)."""
    cells = [(cols[i], top, h) for i, h in enumerate(header)]
    for r, row in enumerate(body):
        for i, v in enumerate(row):
            if v:
                cells.append((cols[i], top - (r + 1) * pitch, v))
    return cells


COLS4 = [55, 175, 275, 460]
HEADER4 = ["Vulnerability", "Product", "Affected Version", "Fixed Version"]


def write_pdf(tmp_path, pages, name="t.pdf") -> str:
    path = tmp_path / name
    path.write_bytes(build_pdf(pages))
    return str(path)


# ── 기하 복원 (ASCII 픽스처) ──────────────────────────────────────────────────

def test_four_column_table_is_recovered(tmp_path):
    body = [["CVE-2026-8461", "FFmpeg", "8.1.0 to 8.1.2", "8.1.2"],
            ["CVE-2026-9001", "OpenSSL", "3.0.0 to 3.0.14", "3.0.15, 3.1.7"]]
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [layout(COLS4, HEADER4, body)]))
    assert res.status == TABLE_OK, res
    assert len(res.rows) == 2
    assert res.rows[0].cve == "CVE-2026-8461"
    assert res.rows[0].product == "FFmpeg"
    assert res.rows[0].affected == "8.1.0 to 8.1.2"
    assert res.rows[0].fixed == "8.1.2"
    assert res.rows[1].product == "OpenSSL"
    assert res.rows[1].fixed == "3.0.15, 3.1.7"


def test_merged_cells_are_forward_filled(tmp_path):
    """사용자 예시 그대로 — 같은 제품에 범위가 둘, 2행은 취약점·제품명이 병합돼 비어 있다."""
    body = [["CVE-2026-8461", "FFmpeg", "8.1.0 to 8.1.2", "8.1.2"],
            ["", "", "8.0.0 to 8.0.3", "8.1.3"]]
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [layout(COLS4, HEADER4, body)]))
    assert res.status == TABLE_OK
    assert len(res.rows) == 2
    assert res.rows[1].cve == "CVE-2026-8461", "병합셀이 상속되지 않았다"
    assert res.rows[1].product == "FFmpeg"
    assert res.rows[1].affected == "8.0.0 to 8.0.3"
    assert res.rows[1].fixed == "8.1.3"


def test_three_column_table_without_cve_column(tmp_path):
    cols = [55, 230, 430]
    header = ["Product", "Affected Version", "Fixed Version"]
    body = [["Apache Tomcat", "under 9.0.90", "9.0.90"]]
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [layout(cols, header, body)]))
    assert res.status == TABLE_OK, res
    assert len(res.rows) == 1
    assert res.rows[0].product == "Apache Tomcat"
    assert res.rows[0].affected == "under 9.0.90"
    assert res.rows[0].cve == ""


def test_prose_around_table_is_ignored(tmp_path):
    """표 위 제목·설명과 아래 안내문이 행으로 섞여 들어오면 안 된다."""
    cells = [(55, 790, "Security Advisory 2026-06"),
             (55, 765, "The following products are affected by these issues.")]
    cells += layout(COLS4, HEADER4, [["CVE-2026-8461", "FFmpeg", "8.1.0 to 8.1.2", "8.1.2"]])
    cells.append((55, 560, "Please apply the patches as soon as possible."))
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [cells]))
    assert res.status == TABLE_OK
    assert len(res.rows) == 1, [(r.product, r.affected) for r in res.rows]
    assert "Please apply" not in res.rows[0].product


def test_wrapped_cell_is_merged_into_previous_row(tmp_path):
    """긴 셀이 다음 줄로 넘어간 경우 — 새 행이 아니라 앞 행에 이어붙어야 한다."""
    cells = layout(COLS4, HEADER4, [["CVE-2026-7777", "Apache Tomcat", "under 9.0.90", "9.0.90"]])
    cells.append((275, 700 - 2 * 22, "and earlier releases"))   # affected 열 아래 줄
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [cells]))
    assert res.status == TABLE_OK
    assert len(res.rows) == 1, [(r.product, r.affected) for r in res.rows]
    assert res.rows[0].affected == "under 9.0.90 and earlier releases"


def test_numbers_are_not_split_by_spurious_spaces(tmp_path):
    """좌표로 띄어쓰기를 재구성하면 '8.1 .0' 처럼 숫자가 벌어진다 — 정리돼야 한다."""
    body = [["CVE-2026-1111", "Node.js", "20.11.0 to 20.11.2", "20.11.3"]]
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [layout(COLS4, HEADER4, body)]))
    assert res.status == TABLE_OK
    assert res.rows[0].affected == "20.11.0 to 20.11.2"
    assert res.rows[0].fixed == "20.11.3"


def test_multi_page_table_continues(tmp_path):
    p1 = layout(COLS4, HEADER4, [["CVE-2026-0001", "ProductA", "1.0 to 1.2", "1.2"]])
    p2 = layout(COLS4, HEADER4, [["CVE-2026-0002", "ProductB", "2.0 to 2.4", "2.4"]])
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [p1, p2]))
    assert res.status == TABLE_OK
    assert res.pages_scanned == 2
    products = [r.product for r in res.rows]
    assert products == ["ProductA", "ProductB"], products
    assert [r.page for r in res.rows] == [0, 1]


def test_no_header_is_reported_as_no_table(tmp_path):
    cells = [(55, 700, "This advisory describes CVE-2026-8461 in FFmpeg 8.1.0."),
             (55, 680, "Update to version 8.1.2 or later.")]
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [cells]))
    assert res.status == NO_TABLE
    assert res.rows == []


def test_header_without_body_is_reported_as_unparsed(tmp_path):
    res = pdf_tables.extract_tables(write_pdf(tmp_path, [layout(COLS4, HEADER4, [])]))
    assert res.status == TABLE_UNPARSED
    assert res.rows == []
    assert res.header_labels


def test_broken_file_does_not_raise(tmp_path):
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-1.4\nnot really a pdf")
    res = pdf_tables.extract_tables(str(path))
    assert res.status == NO_TABLE


def test_missing_file_does_not_raise():
    assert pdf_tables.extract_tables("/nonexistent/nope.pdf").status == NO_TABLE


# ── 한글 헤더 키워드 (PDF 를 거치지 않는 순수 단위 테스트) ─────────────────────

@pytest.mark.parametrize("labels", [
    ["취약점", "제품명", "영향받는 버전", "해결 버전"],
    ["취약점 번호", "대상 제품", "취약 버전", "조치 버전"],
    ["CVE", "영향 제품", "해당 버전", "패치 버전"],
    ["제품명", "영향받는 버전"],                          # 최소 구성(2열)
    ["순번", "제품", "영향받는버전", "해결버전", "심각도"],  # 여분 열 포함
])
def test_korean_headers_are_recognised(labels):
    cells = [(55.0 + i * 120, label) for i, label in enumerate(labels)]
    found = pdf_tables._classify_header(cells)
    assert found is not None, labels
    assert "product" in found and "affected" in found


@pytest.mark.parametrize("labels", [
    ["번호", "제목", "작성일"],          # 전혀 다른 표
    ["제품명", "담당부서"],              # 버전 열이 없음
    ["영향받는 버전", "해결 버전"],       # 제품 열이 없음
])
def test_non_product_tables_are_rejected(labels):
    cells = [(55.0 + i * 120, label) for i, label in enumerate(labels)]
    assert pdf_tables._classify_header(cells) is None, labels


def test_header_role_takes_leftmost_when_split():
    """'영향받는' '버전' 이 두 셀로 쪼개져도 왼쪽 x 를 앵커로 잡아야 한다."""
    cells = [(55.0, "제품명"), (200.0, "영향받는"), (250.0, "버전")]
    found = pdf_tables._classify_header(cells)
    assert found is not None
    assert found["affected"] == 200.0


@pytest.mark.parametrize(("raw", "expected"), [
    ("8.1 .0 to 8.1 .2", "8.1.0 to 8.1.2"),
    ("1 0.1 .25", "10.1.25"),
    ("3.0.1 5, 3.1 .7", "3.0.15, 3.1.7"),
    ("8.1.0 이상 8.1.2 미만", "8.1.0 이상 8.1.2 미만"),
    ("특정 버전으로 마이그레이션", "특정 버전으로 마이그레이션"),
])
def test_tidy_absorbs_spurious_spaces_in_numbers(raw, expected):
    assert pdf_tables._tidy(raw) == expected

"""좌표 기반 PDF 표 복원 — 보안권고문의 주 서식인 표에서 행·열을 되살린다.

왜 필요한가
    extract.py 의 본문 추출은 pypdf `extract_text()` 로 평문만 뽑는다. 권고문의 주 서식

        | 취약점 | 제품명 | 영향받는 버전 | 해결 버전 |
        | CVE-2026-8461 | FFmpeg | 8.1.0 이상 8.1.2 미만 | 8.1.2 |

    이 평문화되면 열 구조가 사라져, 제품명 칸과 버전 칸이 뒤섞인 텍스트에서 정규식이
    엉뚱한 조합을 잡거나 아무것도 못 잡는다. 여기서는 pypdfium2 의 문자 좌표
    (`get_charbox`)로 행·열을 복원해 셀 단위로 넘겨준다. 새 의존성은 없다.

알고리즘 (프로토타입으로 검증)
    1. 문자별 (글자, x0, x1, y0, y1) 수집
    2. 행 복원 — 세로 '중심'((y0+y1)/2) 기준 클러스터링.
       y0(밑변) 기준으로 하면 디센더(p·g·y)가 같은 줄을 두 줄로 쪼갠다.
    3. 열 앵커 — 헤더 행을 키워드로 찾아 그 셀들의 시작 x 를 열 기준선으로 삼는다.
       페이지 전체의 '세로 여백 통로'를 찾는 방식은 표 위·아래 산문이 통로를 가로질러
       열 경계를 통째로 놓친다(실측 확인).
    4. 본문 행을 앵커에 배정 + 병합셀 forward-fill + 줄바꿈 셀 병합

한계
    · 스캔본(이미지) PDF 는 문자가 없어 NO_TABLE 이 된다 — OCR 은 범위 밖.
    · 셀 경계선(괘선)은 보지 않는다. 텍스트 배치만으로 판단한다.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

# pdfium 은 스레드 안전이 아니다. 추출은 ThreadPoolExecutor 에서 돌고 페이지 렌더도
# 동시에 일어날 수 있으므로, pdf_render 와 '같은' 락을 공유해 전 pdfium 호출을 직렬화한다.
from .pdf_render import _LOCK as _PDFIUM_LOCK

# 상한 — 방어적 코딩(대용량/악성 PDF 로 워커가 묶이지 않게).
MAX_PAGES = 30
MAX_CHARS_PER_PAGE = 20_000

TABLE_OK = "TABLE_OK"
NO_TABLE = "NO_TABLE"              # 헤더 행을 못 찾음 = 표 형태가 아님
TABLE_UNPARSED = "TABLE_UNPARSED"  # 헤더는 찾았으나 유효 본문 행 0건

CVE_RE = re.compile(r"CVE[\s\-_]?\d{4}[\s\-_]?\d{4,7}", re.IGNORECASE)
# 버전처럼 보이는 토큰(숫자.숫자 / 4자리 연도 / 23H2 류). 표 본문 행 판정에만 쓴다.
VERSION_HINT_RE = re.compile(r"\d+\s*\.\s*\d+|\b\d{4}\b|\b\d{2}H\d\b", re.IGNORECASE)

# 헤더 열 키워드. 공백을 제거한 뒤 부분일치로 본다(한/영 혼용 권고문 대응).
COLUMN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "cve": ("취약점", "취약점번호", "cve", "vulnerability", "취약성"),
    "product": ("제품", "제품명", "대상제품", "영향제품", "영향받는제품", "product", "소프트웨어"),
    "affected": ("영향", "영향받는버전", "취약버전", "대상버전", "해당버전", "affected", "vulnerableversion"),
    "fixed": ("해결", "해결버전", "조치", "조치버전", "패치", "패치버전", "업데이트버전",
              "fixed", "patched", "fixedversion"),
}
# 이 둘이 모두 잡혀야 표로 인정한다. 취약점·해결 열은 없을 수 있다(3열 표).
REQUIRED_COLUMNS = ("product", "affected")


@dataclass
class TableRow:
    """복원된 표 한 행 — 열 역할별 셀 텍스트."""
    cve: str = ""
    product: str = ""
    affected: str = ""
    fixed: str = ""
    page: int = 0

    def is_empty(self) -> bool:
        return not (self.product or self.affected or self.fixed or self.cve)


@dataclass
class TableExtraction:
    rows: list[TableRow] = field(default_factory=list)
    status: str = NO_TABLE
    pages_scanned: int = 0
    header_labels: list[str] = field(default_factory=list)
    truncated: bool = False       # 상한에 걸려 중단됐는지(부분 결과임을 호출측에 알림)


# ── 1) 문자 수집 ──────────────────────────────────────────────────────────────

def _page_chars(textpage) -> list[tuple[str, float, float, float, float]]:
    """(글자, x0, x1, y0, y1) 목록. 공백류는 버린다(좌표로 띄어쓰기를 재구성하므로)."""
    out = []
    n = min(textpage.count_chars(), MAX_CHARS_PER_PAGE)
    for i in range(n):
        try:
            ch = textpage.get_text_range(i, 1)
        except Exception:  # noqa: BLE001 — 깨진 글리프 하나가 전체 추출을 막지 않게
            continue
        if not ch or not ch.strip():
            continue
        try:
            x0, y0, x1, y1 = textpage.get_charbox(i)
        except Exception:  # noqa: BLE001
            continue
        if x1 < x0:
            x0, x1 = x1, x0
        if y1 < y0:
            y0, y1 = y1, y0
        out.append((ch, x0, x1, y0, y1))
    return out


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[len(s) // 2]


# ── 2) 행 복원 ────────────────────────────────────────────────────────────────

def _group_rows(chars, tol: float) -> list[list[tuple]]:
    """세로 중심이 tol 이내인 문자들을 한 행으로. 위에서 아래 순서로 반환."""
    rows: list[tuple[float, list]] = []
    for c in sorted(chars, key=lambda c: -((c[3] + c[4]) / 2)):
        mid = (c[3] + c[4]) / 2
        if rows and abs(rows[-1][0] - mid) <= tol:
            rows[-1][1].append(c)
        else:
            rows.append((mid, [c]))
    return [sorted(cs, key=lambda c: c[1]) for _, cs in rows]


def _row_centers(chars, tol: float) -> list[float]:
    centers: list[float] = []
    for c in sorted(chars, key=lambda c: -((c[3] + c[4]) / 2)):
        mid = (c[3] + c[4]) / 2
        if not centers or abs(centers[-1] - mid) > tol:
            centers.append(mid)
    return centers


# ── 3) 셀 분할 ────────────────────────────────────────────────────────────────

def _segments(row, gap: float, space_gap: float) -> list[tuple[float, str]]:
    """행을 셀로 분할 → [(시작 x, 텍스트)].

    gap 이상 벌어지면 셀 경계, space_gap 이상이면 같은 셀 안의 띄어쓰기로 본다.
    임계값은 문자 '폭' 기준이다 — 높이 기준으로 하면 좁은 글리프(., 1) 주변에서
    숫자 내부가 쪼개진다("8.1 .0").
    """
    cells: list[tuple[float, str]] = []
    cur = ""
    start = None
    prev_end = None
    for ch, x0, x1, _y0, _y1 in row:
        if prev_end is not None and x0 - prev_end > gap:
            if cur.strip():
                cells.append((start, cur.strip()))
            cur, start = "", None
        if start is None:
            start = x0
        elif prev_end is not None and x0 - prev_end > space_gap and cur and not cur.endswith(" "):
            cur += " "
        cur += ch
        prev_end = x1
    if cur.strip():
        cells.append((start, cur.strip()))
    return cells


def _norm_label(text: str) -> str:
    return re.sub(r"\s+", "", text).lower()


def _classify_header(cells: list[tuple[float, str]]) -> dict[str, float] | None:
    """헤더 후보 행 → {열 역할: 앵커 x}. 필수 열이 없으면 None.

    같은 역할이 여러 셀에 걸리면 가장 왼쪽을 쓴다(예: '영향받는' '버전' 이 쪼개진 경우).
    """
    found: dict[str, float] = {}
    for x, text in cells:
        label = _norm_label(text)
        if not label:
            continue
        for role, keys in COLUMN_KEYWORDS.items():
            if role in found:
                continue
            if any(k in label for k in keys):
                found[role] = x
                break
    if not all(r in found for r in REQUIRED_COLUMNS):
        return None
    return found


def _assign(row, anchors: list[tuple[str, float]], space_gap: float) -> dict[str, str]:
    """행의 문자들을 앵커(열)에 배정 → {역할: 텍스트}.

    각 문자는 '자신의 x 이하인 앵커 중 가장 오른쪽'에 들어간다. 앵커보다 살짝 왼쪽에서
    시작하는 셀(중앙 정렬 등)을 흡수하려 약간의 여유를 둔다.
    """
    buckets: dict[str, str] = {role: "" for role, _ in anchors}
    prev_end: dict[str, float] = {}
    for ch, x0, x1, _y0, _y1 in row:
        role = anchors[0][0]
        for r, ax in anchors:
            if x0 >= ax - space_gap * 2:
                role = r
        pe = prev_end.get(role)
        if pe is not None and x0 - pe > space_gap and buckets[role] and not buckets[role].endswith(" "):
            buckets[role] += " "
        buckets[role] += ch
        prev_end[role] = x1
    return {r: v.strip() for r, v in buckets.items()}


def _looks_like_body(cells: dict[str, str]) -> bool:
    """표 본문 행인가 — CVE 코드나 버전스러운 토큰이 있어야 한다.

    표 아래 산문 한 줄이 열에 걸쳐 잘려 들어오는 것을 막는 1차 방어선이다.
    """
    joined = " ".join(cells.values())
    return bool(CVE_RE.search(joined) or VERSION_HINT_RE.search(joined))


def _tidy(text: str) -> str:
    """셀 텍스트 정리 — 숫자·점 주변의 가짜 공백을 흡수한다.

    좌표로 띄어쓰기를 재구성하다 보면 좁은 글리프 주변에서 '8.1 .0', '1 0.1' 처럼
    숫자 내부가 벌어진다. 버전 파서가 오해하지 않도록 여기서 붙인다.
    """
    text = re.sub(r"\s+", " ", text).strip()
    for _ in range(3):   # '1 0 . 1 . 2' 처럼 여러 번 벌어진 경우까지 수렴
        new = re.sub(r"(?<=\d)\s+(?=[.\d])|(?<=[.])\s+(?=\d)", "", text)
        if new == text:
            break
        text = new
    return text


# ── 4) 페이지 처리 ────────────────────────────────────────────────────────────

def _extract_page(chars, page_index: int, anchors: list[tuple[str, float]] | None):
    """한 페이지에서 (행 목록, 앵커, 헤더 라벨) 추출. 앵커를 주면 이어받아 계속한다."""
    if not chars:
        return [], anchors, []

    heights = [c[4] - c[3] for c in chars]
    widths = [c[2] - c[1] for c in chars]
    med_h = _median(heights) or 8.0
    med_w = _median(widths) or 5.0
    row_tol = med_h * 0.6
    cell_gap = max(med_w * 2.5, med_h * 1.2)
    space_gap = med_w * 0.6

    rows = _group_rows(chars, row_tol)
    centers = _row_centers(chars, row_tol)
    pitches = [abs(centers[i] - centers[i + 1]) for i in range(len(centers) - 1)]
    med_pitch = _median(pitches) or med_h * 2

    header_labels: list[str] = []
    start = 0
    if anchors is None:
        for i, row in enumerate(rows):
            cells = _segments(row, cell_gap, space_gap)
            if len(cells) < 2:
                continue
            found = _classify_header(cells)
            if found:
                anchors = sorted(found.items(), key=lambda kv: kv[1])
                header_labels = [t for _, t in cells]
                start = i + 1
                break
        if anchors is None:
            return [], None, []
    else:
        # 이어지는 페이지: 첫 행이 헤더 반복이면 건너뛴다.
        for i, row in enumerate(rows[:3]):
            if _classify_header(_segments(row, cell_gap, space_gap)):
                start = i + 1
                break

    out: list[TableRow] = []
    carry = {"cve": "", "product": "", "affected": "", "fixed": ""}
    misses = 0
    prev_center = centers[start] if start < len(centers) else None

    for i in range(start, len(rows)):
        row = rows[i]
        center = centers[i] if i < len(centers) else None
        # 행 간격이 갑자기 크게 벌어지면 표가 끝난 것으로 본다.
        if prev_center is not None and center is not None and med_pitch > 0:
            if abs(prev_center - center) > med_pitch * 2.2:
                break
        prev_center = center

        cells = {r: _tidy(v) for r, v in _assign(row, anchors, space_gap).items()}
        for role in ("cve", "product", "affected", "fixed"):
            cells.setdefault(role, "")
        if not any(cells.values()):
            continue

        if not _looks_like_body(cells):
            # 버전도 CVE 도 없는 행 — 줄바꿈된 셀의 뒷부분일 수 있다.
            filled = [r for r in ("product", "affected", "fixed") if cells[r]]
            if out and len(filled) == 1:
                role = filled[0]
                setattr(out[-1], role, _tidy(f"{getattr(out[-1], role)} {cells[role]}"))
                misses = 0
                continue
            misses += 1
            if misses >= 2:
                break
            continue
        misses = 0

        # 병합셀 — 빈 칸은 직전 행 값을 물려받는다.
        for role in ("cve", "product"):
            if cells[role]:
                carry[role] = cells[role]
            else:
                cells[role] = carry[role]

        tr = TableRow(cve=cells["cve"], product=cells["product"],
                      affected=cells["affected"], fixed=cells["fixed"], page=page_index)
        if not tr.is_empty():
            out.append(tr)

    return out, anchors, header_labels


# ── 5) 공개 API ───────────────────────────────────────────────────────────────

def extract_tables(pdf_path: str) -> TableExtraction:
    """PDF 에서 제품·버전 표를 복원. 실패해도 예외를 올리지 않는다(추출 전체를 막지 않게)."""
    import pypdfium2 as pdfium

    result = TableExtraction()
    try:
        with _PDFIUM_LOCK:
            doc = pdfium.PdfDocument(pdf_path)
            try:
                total = len(doc)
                result.truncated = total > MAX_PAGES
                anchors = None
                for pi in range(min(total, MAX_PAGES)):
                    page = doc[pi]
                    tp = page.get_textpage()
                    try:
                        chars = _page_chars(tp)
                    finally:
                        tp.close()
                    result.pages_scanned = pi + 1
                    rows, anchors, labels = _extract_page(chars, pi, anchors)
                    if labels and not result.header_labels:
                        result.header_labels = labels
                    result.rows.extend(rows)
                    # 헤더를 아직 못 찾았고 본문도 없으면 다음 페이지로 계속 탐색.
            finally:
                doc.close()
    except Exception:  # noqa: BLE001 — 손상 PDF 등은 '표 없음'으로 떨어뜨린다
        return TableExtraction(status=NO_TABLE)

    if not result.header_labels:
        result.status = NO_TABLE
    elif not result.rows:
        result.status = TABLE_UNPARSED
    else:
        result.status = TABLE_OK
    return result

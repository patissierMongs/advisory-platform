"""헤더 자동 감지 — 병합 제목행(forward-fill 복제)이 헤더 점수를 탈취하지 않는지."""
from __future__ import annotations

from app.core.assets_import import detect_header_row


def _title_fill(text: str, width: int) -> list:
    """가로 병합 제목행이 _load_sheet 의 forward-fill 을 거친 뒤의 모습."""
    return [text] * width


def test_merged_title_row_does_not_beat_real_header():
    # 제목에 '부서'(별칭 단어) 포함 — 10칸 복제돼도 유니크 1개로 접혀 헤더행이 이겨야 한다.
    title = "2026 상반기 전사 자산관리대장 — 정보보호팀 취합본 (부서 제출 원본 병합)"
    grid = [
        _title_fill(title, 10),
        [None] * 10,
        ["자산번호", "사용부서", "시스템 정보", "시스템 정보", "담당자 정보",
         "담당자 정보", "담당자 정보", "IP 주소", "구매년도", "비고"],
        ["자산번호", "사용부서", "제품/OS", "버전", "이름", "소속팀", "연락처",
         "IP 주소", "구매년도", "비고"],           # 세로 병합 fill 후의 하단 헤더
        ["A-1001", "재무팀", "Windows 11", "23H2", "김영수", "재무1셀",
         "010-1111-0001", "10.10.1.11", 2023, None],
    ]
    assert detect_header_row(grid) == 3   # 하단(합성) 헤더행 — 제목행(0)이 아님


def test_plain_single_header_still_detected():
    grid = [
        ["부서별 SW 자산 목록"],
        ["자산번호", "부서", "제품", "버전", "담당자"],
        ["A-1", "총무팀", "Chrome", "124", "김담당"],
    ]
    assert detect_header_row(grid) == 1

"""data 폴더 접근 제한 검증.

운영 타깃은 Windows 지만 CI/개발은 리눅스라, 실제 icacls 실행 대신 명령 조립 로직을
검증한다. 여기서 틀리면 조용히 '적용된 것처럼' 보이면서 실제로는 아무도 막지 못한다.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from app.core import winacl


def test_command_drops_inheritance():
    """/inheritance:r 이 없으면 상위 폴더에서 내려오는 Users 읽기 권한이 그대로 남는다.

    grant 만 걸고 상속을 끊지 않는 것이 이 종류 설정에서 가장 흔한 무력화 실수다.
    """
    args = winacl.build_icacls_args(Path(r"C:\advisory\data"), "CORP\\svc")
    assert "/inheritance:r" in args
    assert args.index("/inheritance:r") < args.index("/grant:r")


def test_command_uses_well_known_sids_not_localized_names():
    """한국어 Windows 에서 'Administrators' 문자열은 통하지 않는다 — SID 여야 한다."""
    args = winacl.build_icacls_args(Path(r"C:\advisory\data"), "CORP\\svc")
    joined = " ".join(args)
    assert "*S-1-5-18:(OI)(CI)F" in joined          # SYSTEM
    assert "*S-1-5-32-544:(OI)(CI)F" in joined      # Administrators
    assert "Administrators:" not in joined
    assert "Everyone" not in joined and "Users:" not in joined


def test_command_grants_running_account_and_inherits():
    args = winacl.build_icacls_args(Path(r"C:\advisory\data"), "CORP\\svc")
    assert "CORP\\svc:(OI)(CI)F" in args            # 구동 계정이 자기 데이터를 못 읽으면 앱이 죽는다
    assert "/T" in args                             # 이미 존재하는 하위 항목까지 적용


def test_command_omits_account_when_unknown():
    """계정 판별 실패 시 빈 ACE 를 넣으면 icacls 가 통째로 실패한다 — 생략해야 한다."""
    args = winacl.build_icacls_args(Path(r"C:\advisory\data"), None)
    assert not any(a.endswith(":(OI)(CI)F") and a.startswith("\\") for a in args)
    assert sum(1 for a in args if a.endswith("(OI)(CI)F")) == 2


def test_path_passed_as_single_argv_entry():
    """공백·한글 경로가 셸 파싱으로 쪼개지지 않아야 한다(shell=False 전제)."""
    p = Path(r"C:\Program Files\보안권고문\data")
    args = winacl.build_icacls_args(p, "CORP\\svc")
    assert str(p) in args


def test_harden_dir_is_idempotent_via_sentinel(tmp_path, monkeypatch):
    """매 기동마다 icacls 를 다시 돌리지 않는다(표식 파일)."""
    calls = []
    monkeypatch.setattr(winacl.sys, "platform", "win32")
    monkeypatch.setattr(winacl.subprocess, "run",
                        lambda *a, **k: calls.append(a) or _ok())
    assert winacl.harden_dir(tmp_path) is True
    assert (tmp_path / winacl.SENTINEL_NAME).exists()
    assert winacl.harden_dir(tmp_path) is True
    assert len(calls) == 1, "표식이 있는데 재실행했다"
    assert winacl.harden_dir(tmp_path, force=True) is True
    assert len(calls) == 2, "force 가 무시됐다"


def test_harden_dir_failure_does_not_raise(tmp_path, monkeypatch, capsys):
    """ACL 적용 실패로 서버가 안 뜨면 그게 더 큰 사고다 — 경고만 남기고 계속."""
    monkeypatch.setattr(winacl.sys, "platform", "win32")
    monkeypatch.setattr(winacl.subprocess, "run",
                        lambda *a, **k: _fail("access denied"))
    assert winacl.harden_dir(tmp_path) is False
    out = capsys.readouterr().out
    assert "경고" in out
    assert "icacls" in out, "수동 복구 명령이 안내되지 않았다"
    assert not (tmp_path / winacl.SENTINEL_NAME).exists(), "실패했는데 성공 표식이 남았다"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX 폴백 경로 검증")
def test_posix_fallback_sets_0700(tmp_path):
    target = tmp_path / "data"
    target.mkdir()
    assert winacl.harden_dir(target) is True
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o700


class _Result:
    def __init__(self, code, out="", err=""):
        self.returncode, self.stdout, self.stderr = code, out, err


def _ok():
    return _Result(0)


def _fail(msg):
    return _Result(1, err=msg)

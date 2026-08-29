"""Regression test for rdbparse against the aplikace_pcfand sample corpus."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import rdbparse as R

SAMPLE_DIR = ROOT / "aplikace_pcfand"


def _names(data: bytes):
    _, _, records = R.parse_rdb(data)
    return [R._record_name(rec) for rec in records]


def test_pokusha_header_and_catalog():
    data = (SAMPLE_DIR / "POKUSHA.rdb").read_bytes()
    nrecs, reclen, records = R.parse_rdb(data)
    assert nrecs == 2
    assert reclen == 24
    assert _names(data) == ["FSoubor", "PMain"]


def test_pokus_has_code_table():
    data = (SAMPLE_DIR / "POKUS.rdb").read_bytes()
    assert _names(data) == ["FSoubor", "FSoubSif", "PMain"]


def test_format_rdb_runs():
    out = R.format_rdb((SAMPLE_DIR / "POKUS.rdb").read_bytes())
    assert "FSoubor" in out
    assert "FSoubSif" in out

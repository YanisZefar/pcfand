"""Regression tests for xdecode using the aplikace_pcfand sample corpus.

The samples are the *same task* exported from PC FAND with different encodings:
  * POKUSHA/B/C/HAB  -> XOR-AA (password/"zaheslovaná") TFile records
  * POKUSSI2         -> XEncode (licensed/rotated) TFile record
  * POKUS.ttt        -> plaintext (unencoded) TFile records
  * SOUBOR.T00       -> plaintext TFile record

Before the plaintext branch was added, POKUS.ttt and SOUBOR.T00 decoded to
zero bytes because decode_tfile only tried xor-aa and x.
"""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import xdecode as X

SAMPLE_DIR = ROOT / "aplikace_pcfand"

# name -> substring that must appear in the decoded FAND source text
SAMPLES = {
    "POKUSHA.ttt": b"Polo\xa7ka :A,10;",
    "POKUSHB.ttt": b"Polo\xa7ka :A,10;",
    "POKUSHC.ttt": b"Polo\xa7ka :A,10;",
    "POKUSHAB.ttt": b"Polo\xa7ka :A,10;",
    "POKUSSI2.ttt": b"var AAAAAAAAAA:real;",
    "POKUS.ttt": b"Polo\xa7kaA :A,10;",
    "SOUBOR.T00": b"abcdefg",
}


@pytest.fixture(autouse=True)
def _enable_all_formats():
    # Library call: exercise every transform (x, xor-aa, plaintext).
    X.args_format_is_x = True
    X.args_format_is_xor_aa = True
    yield
    X.args_format_is_x = False
    X.args_format_is_xor_aa = False


@pytest.mark.parametrize("name,marker", list(SAMPLES.items()))
def test_sample_decodes_to_text(name, marker):
    data = (SAMPLE_DIR / name).read_bytes()
    out = X.decode_tfile(data)
    assert out, f"{name} produced no decoded output"
    assert marker in out, f"{name} is missing expected marker {marker!r}"


def test_plaintext_record_in_tfile():
    """A TFile whose record is stored unencoded (plaintext) must decode."""
    payload = b"begin end;\n"
    page0 = b"\x00" * 512
    record = len(payload).to_bytes(2, "little") + payload
    # pad the second page so reassembly does not need chaining
    page1 = record + b"\x00" * (512 - len(record))
    data = page0 + page1
    out = X.decode_tfile(data)
    assert out.startswith(payload), f"unexpected plaintext decode: {out!r}"


def test_looks_like_text_rejects_embedded_nul():
    assert X._looks_like_text(b"Polo\xa7ka :A,10;\r\nbegin end;\n") is True
    assert X._looks_like_text(b"\x00\x00\x08Polo\xa7ka") is False

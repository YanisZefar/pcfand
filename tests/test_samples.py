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


def test_parse_catalog_pokus():
    import rdbparse as R

    cat = R.parse_catalog((SAMPLE_DIR / "POKUS.rdb").read_bytes())
    assert [c["name"] for c in cat] == ["FSoubor", "FSoubSif", "PMain"]
    # TxtPos values are the absolute offsets into the paired .ttt
    assert cat[0]["txtpos"] == 1798
    assert cat[2]["txtpos"] == 642


def test_decode_tfile_cataloged_pokus():
    ttt = (SAMPLE_DIR / "POKUS.ttt").read_bytes()
    rdb = (SAMPLE_DIR / "POKUS.rdb").read_bytes()
    out = X.decode_tfile_cataloged(ttt, rdb)
    chapters = sum(1 for ln in out.split(b"\n") if ln.startswith(b"### "))
    assert chapters == 3, f"expected 3 catalog chapters, got {chapters}"
    assert b"### FSoubor" in out
    assert b"### PMain" in out
    # LicNr for POKUS is 0, so pos == txtpos
    assert b"licnr=0" in out


def test_decode_tfile_cataloged_kabely_count():
    ttt = (SAMPLE_DIR / "KABELY2.TTT").read_bytes()
    rdb = (SAMPLE_DIR / "KABELY2.RDB").read_bytes()
    out = X.decode_tfile_cataloged(ttt, rdb)
    # All 78 member sources decoded, no blind-scan false positives
    chapters = sum(1 for ln in out.split(b"\n") if ln.startswith(b"### "))
    assert chapters == 78, f"expected 78 catalog chapters, got {chapters}"
    assert b"Jmeno_Serveru" in out


def test_rebuild_tfile_no_size_explosion():
    ttt = (SAMPLE_DIR / "KABELY2.TTT").read_bytes()
    rebuilt = X.rebuild_tfile(ttt)
    # Rebuild must stay within a sane multiple of the input size
    # (the old bug produced a ~37 MB file from a 149 KB input).
    assert len(rebuilt) < len(ttt) * 4


def test_write_chapters(tmp_path):
    ttt = (SAMPLE_DIR / "POKUS.ttt").read_bytes()
    rdb = (SAMPLE_DIR / "POKUS.rdb").read_bytes()
    outdir = tmp_path / "chapters"
    written = X.write_chapters(ttt, rdb, outdir)
    files = sorted(p.name for p in outdir.glob("*.txt"))
    assert files == [
        "000_FSoubor.txt",
        "001_FSoubSif.txt",
        "002_PMain.txt",
        "_index.txt",
    ], files
    assert written == [
        "000_FSoubor.txt",
        "001_FSoubSif.txt",
        "002_PMain.txt",
    ]
    # Each member file keeps its original CP852 source bytes.
    assert (outdir / "002_PMAIN.txt").read_bytes()
    assert "PMAIN" in (outdir / "_index.txt").read_text()


def test_rebuild_tfile_cataloged_roundtrip():
    ttt = (SAMPLE_DIR / "KABELY2.TTT").read_bytes()
    rdb = (SAMPLE_DIR / "KABELY2.RDB").read_bytes()
    new_ttt, new_rdb = X.rebuild_tfile_cataloged(ttt, rdb)

    def bodies(blob):
        return b"\n".join(
            ln for ln in blob.split(b"\n") if not ln.startswith(b"### ")
        )

    orig = X.decode_tfile_cataloged(ttt, rdb)
    reb = X.decode_tfile_cataloged(new_ttt, new_rdb)
    # Every member source must survive the unencrypted rebuild unchanged.
    assert bodies(orig) == bodies(reb)
    # And the regenerated .rdb must list the same member names.
    import rdbparse as R

    assert [c["name"] for c in R.parse_catalog(rdb)] == [
        c["name"] for c in R.parse_catalog(new_rdb)
    ]


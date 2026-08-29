"""Decode a native PC FAND ``.rdb`` data-file (RDB / DBF-style table).

Confirmed from ``EXPIMP.PAS`` ``CheckFile`` (lines 1290-1297):

    Prfx: record NRecs:longint; RecLen:word end;
    ReadH(h,6,Prfx);

so the on-disk layout of every FAND data file is:

    int32   NRecs    number of data records
    uint16  RecLen   length of each record
    then NRecs records of RecLen bytes each (starting at offset 6)

This is a generic table container; the *meaning* of the bytes inside a record
depends on the table's field definitions (which live in the ``.ttt`` source).
For the sample files shipped in ``aplikace_pcfand`` the records happen to be
24 bytes long and carry a 12-byte name at offset 7 identifying a member
file/table of the application (``FSoubor``, ``FSoubSif``, ``PMain``); the
rest is per-record metadata. So these particular ``.rdb`` files are the
application's *file/member catalog*.

FAND's own system catalog (``CatFD``) chains five fields in this order
(``RUNFAND.PAS`` lines 247-248)::

    CatRdbName -> CatFileName -> CatArchiv -> CatPathName -> CatVolume

``UpdateCat`` (``PROJMGR.PAS`` line 521) drives this catalog through the normal
data-file editor (``AllFldsList(CatFD)``), so the *byte offsets* of those
fields are **data-driven** (stored in the RDB's field dictionary), not hardcoded
in the sources.

The sample ``.rdb`` records are 24 bytes with the readable 12-byte name at
offset 7 (not at offset 0), which fits a *condensed* catalog where the first
field is numeric, not a string. The most source-consistent interpretation is:

    offset 0-5 (f0,f1,f2) : CatRdbName  (numeric reference to the owning RDB)
    offset 6        (f3)   : reserved (0x00)
    offset 7-18     (name) : CatFileName (member file/table name)  [confirmed readable]
    offset 19-23    (tail) : CatArchiv / CatPathName / CatVolume  (condensed metadata)

The exact role of each individual word/tail byte cannot be pinned from the
sources alone because the layout is data-driven; ``f2`` varying as
0 (PMain=program) / 12 (FSoubSif) / 2,10,91 (FSoubor) is consistent with a
per-member-file record count / size, but that remains an inference.

This is intentionally a separate tool from ``xdecode.py``: ``.rdb`` is
structured binary data, not recoverable source text.

Usage:
    python3 rdbparse.py app.rdb
    python3 rdbparse.py app.rdb out.txt
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def parse_rdb(data: bytes) -> "tuple[int, int, list[bytes]]":
    """Return ``(nrecs, reclen, records)`` for a FAND ``.rdb`` data file."""
    if len(data) < 6:
        raise ValueError("file too small to be an RDB data file")
    nrecs = struct.unpack_from("<i", data, 0)[0]
    reclen = struct.unpack_from("<H", data, 4)[0]
    if reclen == 0 or 6 + nrecs * reclen > len(data):
        raise ValueError(
            f"inconsistent RDB header: NRecs={nrecs} RecLen={reclen} "
            f"file={len(data)}"
        )
    records = [data[6 + i * reclen: 6 + (i + 1) * reclen] for i in range(nrecs)]
    return nrecs, reclen, records


def _record_name(rec: bytes) -> "str | None":
    """Best-effort extraction of a 12-byte name field at offset 7."""
    if len(rec) < 19:
        return None
    raw = rec[7:19]
    if any(b < 0x20 or b > 0x7E for b in raw):
        return None
    return raw.split(b"\x00")[0].decode("cp852", "replace").rstrip()


def format_rdb(data: bytes) -> str:
    nrecs, reclen, records = parse_rdb(data)
    lines = [f"NRecs={nrecs}  RecLen={reclen}"]
    for i, rec in enumerate(records):
        name = _record_name(rec)
        tag = f" name={name!r}" if name else ""
        # also surface the leading words/byte so the raw layout is visible
        f0 = struct.unpack_from("<H", rec, 0)[0] if len(rec) >= 2 else 0
        f1 = struct.unpack_from("<H", rec, 2)[0] if len(rec) >= 4 else 0
        f2 = struct.unpack_from("<H", rec, 4)[0] if len(rec) >= 6 else 0
        f3 = rec[6] if len(rec) > 6 else 0
        tail_u16 = struct.unpack_from("<H", rec, 19)[0] if len(rec) >= 21 else 0
        lines.append(
            f"  [{i}] raw={rec.hex()}{tag}  "
            f"f0={f0} f1={f1} f2={f2} f3={f3:#04x} tail0={tail_u16}"
        )
    lines.append(
        "  (inferred) f2 ~ number of data records of the member file "
        "(PMain=0 program; f3=0x00 reserved; f0/f1/tail = size/offset/flag metadata)"
    )
    return "\n".join(lines)


def _main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help=".rdb data file")
    ap.add_argument("output", type=Path, nargs="?", help="optional output file")
    args = ap.parse_args()
    text = format_rdb(args.input.read_bytes())
    if args.output:
        args.output.write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

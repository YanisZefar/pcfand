"""Decode FAND text segments produced by Code and XEncode.

The X format is the in-memory LongStr representation written by EXPIMP.PAS:
- uint16 little-endian length at offset 0
- encoded payload and random displacement padding
- time byte and XOR-masked displacement trailer

IMPORTANT - password-protected ("nevratně zaheslovaná") applications:
    In PC FAND the password is only an access gate. It is stored separately in
    PwCode/Pw2Code (XOR 0xAA) and verified at runtime via HasPassword, but it
    NEVER enters the encoding transform of the source text records.

    The actual encoding depends only on the build path in CodingCRdb (EXPIMP.PAS):
      * Rotate=false  -> "zaheslovaná" (password only) build
                         source texts encoded with Code() = plain XOR 0xAA
                         => use  --format xor-aa
      * Rotate=true   -> licensed/rotated build (AltF10)
                         source texts encoded with XEncode (compressed LongStr)
                         => use  --format x

    Because the password is not a cryptographic key, a "nevratně zaheslovaná"
    application is fully recoverable: decode it with --format xor-aa (the
    stored password in PwCode is itself XOR 0xAA and is recovered too).

Examples:
    python3 xdecode.py app.rdb out.txt --format xor-aa
    python3 xdecode.py app.rdb out.txt --format x --mode full
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

import rdbparse


class DecodeError(ValueError):
    """Raised when an encoded segment is malformed."""


def _rol8(value: int, count: int) -> int:
    count &= 7
    return ((value << count) | (value >> (8 - count))) & 0xFF if count else value


def decode_xor_aa(data: bytes) -> bytes:
    """Reverse ACCESS.PAS ``Code`` for a byte string."""
    return bytes(value ^ 0xAA for value in data)


def decode_x_segment(segment: bytes) -> bytes:
    """Decode one complete XEncode LongStr segment.

    ``segment`` must contain the two-byte LongStr length, followed by the
    segment bytes and its two-byte trailer displacement.
    """
    if len(segment) < 4:
        raise DecodeError("segment is shorter than a LongStr header and trailer")

    encoded_length = struct.unpack_from("<H", segment)[0]
    expected_size = encoded_length + 2
    if len(segment) < expected_size:
        raise DecodeError(
            f"truncated segment: length says {expected_size} bytes, "
            f"got {len(segment)}"
        )

    trailer_time = segment[encoded_length - 1]
    masked_displacement = struct.unpack_from("<H", segment, encoded_length)[0]
    displacement = masked_displacement ^ 0xCCCC
    payload_start = 2 + displacement
    payload_end = encoded_length - 1
    if payload_start < 2 or payload_start > payload_end:
        raise DecodeError("invalid displacement")

    mask = _rol8(0x9C, trailer_time & 3)
    source = payload_start
    output = bytearray(b"\x00\x00")
    flag_bits = 0
    flag_mask = 0

    while source < payload_end:
        if flag_mask == 0:
            if source >= payload_end:
                break
            flag_bits = segment[source]
            source += 1
            flag_mask = 0x01

        if flag_bits & flag_mask:
            if source + 3 > payload_end:
                raise DecodeError("truncated back-reference token")
            length = segment[source]
            offset = struct.unpack_from("<H", segment, source + 1)[0]
            source += 3
            if length == 0 or offset < 2 or offset >= len(output):
                raise DecodeError("invalid back-reference")
            for _ in range(length):
                if offset >= len(output):
                    raise DecodeError("back-reference exceeds decoded data")
                output.append(output[offset])
                offset += 1
        else:
            if source >= payload_end:
                raise DecodeError("truncated literal token")
            # Mirror EXPIMP.PAS XEncode literal loop exactly:
            #     lodsb; rol RMask,1; xor al,RMask; stosb
            # i.e. rotate the mask BEFORE XOR-ing the byte with it.
            mask = _rol8(mask, 1)
            output.append(segment[source] ^ mask)
            source += 1

        flag_mask <<= 1
        if flag_mask > 0x80:
            flag_mask = 0

    return bytes(output[2:])


def _reassemble_tfile_record(data: bytes, pos: int) -> "bytes | None":
    """Reconstruct one LongStr stored in a TFile (T00Format) page container.

    Mirrors ``TFile.Read`` in FAND's FILEACC.PAS: records are kept in 512-byte
    pages; a record longer than the space left on a page is chained to the next
    page via a 4-byte little-endian page pointer (see ``TFile.RdWr``).
    """
    mpage = 512
    maxl = 65000
    if pos < mpage or pos >= len(data):
        return None
    length = struct.unpack_from("<H", data, pos)[0]
    if length == 0 or length > maxl + 1:
        return None
    if length == maxl + 1:
        length = maxl
    out = bytearray()
    p = pos + 2
    remaining = length
    while remaining > 0:
        rest = mpage - (p & (mpage - 1))
        if remaining > rest - 4:
            chunk = rest - 4
            out += data[p:p + chunk]
            remaining -= chunk
            p += chunk
            if p + 4 > len(data):
                return None
            nxt = struct.unpack_from("<I", data, p)[0]
            p = nxt
            if p < mpage or p >= len(data):
                return None
        else:
            out += data[p:p + remaining]
            remaining = 0
    return bytes(out)


def _looks_like_text(b: bytes) -> bool:
    """Accept a candidate only if it is plausibly FAND source text.

    Real source mixes ASCII keywords/operators with Kamenicky-encoded Czech
    letters (0x80-0xFF). We require a high ratio of printable ASCII *and* at
    least one run of 4+ ASCII letters, which random/garbage data rarely meets.
    """
    if len(b) < 10:
        return False
    if 0 in b:
        # Embedded NULs mark internal sub-structures (record names, pointers),
        # never FAND source text.
        return False
    ascii_frac = sum(1 for x in b if 0x20 <= x <= 0x7E) / len(b)
    if ascii_frac < 0.45:
        return False
    run = 0
    for x in b:
        if 0x41 <= x <= 0x5A or 0x61 <= x <= 0x7A:
            run += 1
            if run >= 4:
                return True
        else:
            run = 0
    return False


def decode_tfile(data: bytes) -> bytes:
    """Decode every text record stored inside a FAND TFile container.

    Scans all candidate record starts, reassembles each LongStr across pages,
    then reverses the XEncode (``--format x``) and XOR-AA (``--format
    xor-aa``) transforms, and also tries the record verbatim. FAND TFfiles may
    mix all three representations per record (a plaintext "Položka :A,10;"
    field stored unencoded next to an XEncode- or XOR-AA-compressed record),
    so whatever yields readable FAND source text is kept.
    """
    out = bytearray()
    seen = set()
    for pos in range(512, len(data) - 4):
        length = struct.unpack_from("<H", data, pos)[0]
        if length < 6 or length > 9000:
            continue
        raw = _reassemble_tfile_record(data, pos)
        if raw is None or len(raw) < 6:
            continue
        candidates = []
        if args_format_is_x:
            try:
                candidates.append(decode_x_segment(struct.pack("<H", length) + raw))
            except DecodeError:
                pass
        if args_format_is_xor_aa:
            candidates.append(decode_xor_aa(raw))
        # Records may also be stored unencoded (plaintext)
        candidates.append(raw)
        for dec in candidates:
            if _looks_like_text(dec) and dec not in seen:
                seen.add(dec)
                out += dec
                out += b"\n"
    return bytes(out)


def _bp7_randstep() -> int:
    """One step of Borland Pascal 7's linear-congruential ``RandSeed`` LCG."""
    global args_randseed
    args_randseed = (args_randseed * 134775813 + 1) & 0xFFFFFFFF
    return (args_randseed >> 16) & 0x7FFF


def _bp7_random(n: int) -> int:
    """``Random(n)`` from BP7: returns a value in ``0..n-1``."""
    return (_bp7_randstep() * n) // 32768


def extract_tfile_records(data: bytes) -> "list[bytes]":
    """Return the raw (still-encoded) LongStr payloads stored in a TFile.

    Mirrors the scan used by ``decode_tfile`` but keeps the stored bytes
    verbatim (so they can be re-packed unchanged).
    """
    out = []
    seen = set()
    for pos in range(512, len(data) - 4):
        length = struct.unpack_from("<H", data, pos)[0]
        if length < 6 or length > 65000:
            continue
        raw = _reassemble_tfile_record(data, pos)
        if raw is None or len(raw) < 6:
            continue
        if raw in seen:
            continue
        seen.add(raw)
        out.append(raw)
    return out


def _build_tfile_page0(licnr: int, mlen: int, time: int) -> bytes:
    """Construct a valid TFile header page (TT1Page) including the WrPrefix scramble.

    ``mlen`` must be the final file size (used as the RNG seed together with
    ``time``), so callers build the record pages first and patch page0 last.
    """
    global args_randseed
    T = bytearray(512)
    struct.pack_into("<H", T, 0, 1)            # Signum
    struct.pack_into("<H", T, 2, 0xFFFF)       # OldMaxPage
    struct.pack_into("<I", T, 4, 512)          # FreePart (= MPageSize, valid per RdPrefix)
    n = 0x6000 if licnr != 0 else 0x4000
    struct.pack_into("<H", T, 11, n)           # IRec (flags)
    struct.pack_into("<I", T, 13, 0)           # FreeRoot
    struct.pack_into("<i", T, 17, (mlen // 512) - 1)  # MaxPage
    T[55:59] = b"FAND"                         # Version
    struct.pack_into("<H", T, 458, licnr & 0xFFFF)     # LicNr (empirical offset)
    T[511] = time & 0xFF                       # Time (used by the RNG seed)
    # WrPrefix: scramble bytes 13..510 (i.e. loop i=14..511) with Random(255).
    # The LicNr at offset 458 must survive the scramble, so we consume the RNG
    # step for it (keeping the stream aligned with FAND's WrPrefix) but do not
    # XOR the field, then write it back explicitly afterwards.
    args_randseed = (mlen + time) & 0xFFFFFFFF
    for off in range(13, 511):
        if off == 458:
            _bp7_random(255)
            continue
        T[off] ^= _bp7_random(255)
    struct.pack_into("<H", T, 458, licnr & 0xFFFF)
    return bytes(T)


def _write_tfile_record(buf: bytearray, rec: bytes) -> int:
    """Append one LongStr record to ``buf`` using 512-byte pages and 4-byte chains.

    Layout mirrors ``_reassemble_tfile_record``: 2-byte length, then data; when a
    record overflows a page the final 4 bytes of that page hold the absolute
    position of the next page. Returns the absolute offset where the record's
    length prefix was written.

    A record must not start so close to a page boundary that its 2-byte length
    prefix would overlap the 4-byte continuation pointer (the last 4 bytes of the
    page). When fewer than 6 bytes remain on the current page the whole record is
    pushed to the next page boundary so the prefix and pointer never collide.
    """
    PAGE = 512
    start = len(buf)
    page_rem = PAGE - (start & (PAGE - 1))
    if page_rem < 6:
        start = (start + PAGE - 1) & ~(PAGE - 1)
        if len(buf) < start:
            buf.extend(b"\x00" * (start - len(buf)))
    buf[start:start + 2] = struct.pack("<H", len(rec))
    p = start + 2
    remaining = len(rec)
    src = 0
    while remaining > 0:
        page_start = (p // PAGE) * PAGE
        rest = PAGE - (p - page_start)
        if remaining > rest - 4:
            chunk = rest - 4
            if len(buf) < p + chunk:
                buf.extend(b"\x00" * (p + chunk - len(buf)))
            buf[p:p + chunk] = rec[src:src + chunk]
            src += chunk
            remaining -= chunk
            p += chunk
            ptr_pos = page_start + PAGE - 4
            next_pos = (page_start // PAGE + 1) * PAGE
            if len(buf) < ptr_pos + 4:
                buf.extend(b"\x00" * (ptr_pos + 4 - len(buf)))
            if len(buf) < next_pos:
                buf.extend(b"\x00" * (next_pos - len(buf)))
            struct.pack_into("<I", buf, ptr_pos, next_pos)
            p = next_pos
        else:
            if len(buf) < p + remaining:
                buf.extend(b"\x00" * (p + remaining - len(buf)))
            buf[p:p + remaining] = rec[src:src + remaining]
            src += remaining
            remaining = 0
    return start


def encode_tfile(records: "list[bytes]", licnr: int = 0, time: int = 0) -> bytes:
    """Pack raw LongStr payloads into a loadable TFile container (``.ttt``)."""
    buf = bytearray(512)  # page0 placeholder
    for rec in records:
        _write_tfile_record(buf, rec)
    if len(buf) % 512:
        buf.extend(b"\x00" * (512 - len(buf) % 512))
    page0 = _build_tfile_page0(licnr, len(buf), time)
    buf[0:512] = page0
    return bytes(buf)


def extract_tfile_texts(data: bytes) -> "list[bytes]":
    """Return the decoded *text* records stored in a TFile, one item per record.

    Mirrors the scan in ``decode_tfile`` (filters by ``_looks_like_text`` and
    de-duplicates) but keeps the individual decoded records separate so they can
    be re-packed, instead of concatenating them into one blob.
    """
    out = []
    seen = set()
    for pos in range(512, len(data) - 4):
        length = struct.unpack_from("<H", data, pos)[0]
        if length < 6 or length > 9000:
            continue
        raw = _reassemble_tfile_record(data, pos)
        if raw is None or len(raw) < 6:
            continue
        candidates = []
        if args_format_is_x:
            try:
                candidates.append(decode_x_segment(struct.pack("<H", length) + raw))
            except DecodeError:
                pass
        if args_format_is_xor_aa:
            candidates.append(decode_xor_aa(raw))
        candidates.append(raw)
        for dec in candidates:
            if _looks_like_text(dec) and dec not in seen:
                seen.add(dec)
                out.append(dec)
                break
    return out


def rebuild_tfile(data: bytes, licnr: int = 0) -> bytes:
    """Re-emit a ``.ttt`` as a loadable *unencrypted* TFile.

    Only genuine FAND source-text records (validated by ``_looks_like_text``)
    are kept; garbage/false-positive positions are dropped. Each stored record
    is decoded (XEncode / XOR-AA / verbatim) to its source text and re-stored
    XOR-AA encoded with ``LicNr=0``; FAND's ``Code`` then reverses XOR-AA on
    load, yielding the plaintext source. The page0 copy-protection scramble is
    reproduced (WrPrefix); full FAND-load verification still requires DOSBox.
    """
    global args_format_is_x, args_format_is_xor_aa
    saved_x, saved_aa = args_format_is_x, args_format_is_xor_aa
    args_format_is_x = True
    args_format_is_xor_aa = True
    try:
        texts = extract_tfile_texts(data)
        out = [decode_xor_aa(t) for t in texts]
        return encode_tfile(out, licnr=licnr)
    finally:
        args_format_is_x, args_format_is_xor_aa = saved_x, saved_aa


def iter_catalog_records(ttt: bytes, rdb: bytes) -> "iter[dict]":
    """Yield one decoded member record per ``.rdb`` catalog entry.

    For each member the catalog lists, compute its exact source position
    (``txtpos - LicNr`` from the ``.ttt`` header @458), reassemble the LongStr
    across 512-byte pages, and decode it with the XEncode / XOR-AA / verbatim
    transforms. Each item is a dict: ``name``, ``txtpos``, ``licnr``, ``pos``,
    ``length`` and ``text`` (the decoded CP852 source bytes).
    """
    global args_format_is_x, args_format_is_xor_aa
    saved_x, saved_aa = args_format_is_x, args_format_is_xor_aa
    args_format_is_x = True
    args_format_is_xor_aa = True
    try:
        licnr = struct.unpack_from("<H", ttt, 458)[0]
        cat = rdbparse.parse_catalog(rdb)
        for entry in cat:
            pos = entry["txtpos"] - licnr
            if pos < 512 or pos >= len(ttt):
                continue
            length = struct.unpack_from("<H", ttt, pos)[0]
            raw = _reassemble_tfile_record(ttt, pos)
            if raw is None or len(raw) < 2:
                continue
            dec = None
            for c in _record_candidates(raw, length):
                if _looks_like_text(c):
                    dec = c
                    break
            if dec is None:
                dec = raw
            yield {
                "name": entry["name"] or f"pos{pos}",
                "txtpos": entry["txtpos"],
                "licnr": licnr,
                "pos": pos,
                "length": length,
                "text": dec,
            }
    finally:
        args_format_is_x, args_format_is_xor_aa = saved_x, saved_aa


def decode_tfile_cataloged(ttt: bytes, rdb: bytes) -> bytes:
    """Decode a FAND TFile using the paired ``.rdb`` member catalog.

    Returns a single blob with one ``### name (...)`` header and the decoded
    source text per member. For per-chapter files use ``write_chapters``.
    """
    out = []
    for rec in iter_catalog_records(ttt, rdb):
        out.append(
            f"### {rec['name']}  (txtpos={rec['txtpos']} licnr={rec['licnr']} "
            f"pos={rec['pos']} len={len(rec['text'])})\n".encode("utf-8")
        )
        out.append(rec["text"])
        out.append(b"\n")
    return b"".join(out)


def write_chapters(ttt: bytes, rdb: bytes, outdir: Path) -> "list[str]":
    """Write each catalog member to its own file inside ``outdir``.

    Files are named ``NNN_sanitizedname.txt`` (zero-padded index + member name)
    and keep the original CP852 source bytes. An ``_index.txt`` mapping is also
    written. Returns the list of written filenames in catalog order.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    records = list(iter_catalog_records(ttt, rdb))
    written = []
    for i, rec in enumerate(records):
        safe = "".join(ch if ch.isalnum() else "_" for ch in rec["name"])
        fname = f"{i:03d}_{safe}.txt"
        (outdir / fname).write_bytes(rec["text"])
        written.append(fname)
    index = "\n".join(
        f"{f}\t{rec['name']}\tpos={rec['pos']}\tlen={len(rec['text'])}"
        for f, rec in zip(written, records)
    )
    (outdir / "_index.txt").write_text(index + "\n", encoding="utf-8")
    return written


def rebuild_tfile_cataloged(ttt: bytes, rdb: bytes) -> "tuple[bytes, bytes]":
    """Re-emit the ``.ttt`` as an unencrypted TFile plus a matching new ``.rdb``.

    Every member record is decoded to its source text and re-stored XOR-AA
    encoded (LicNr=0), appended sequentially into a fresh TFile container. The
    paired ``.rdb`` is rewritten with each member's ``TxtPos`` (u32 @20) updated
    to the new absolute position, so the new ``.ttt``/``.rdb`` pair is internally
    consistent and loadable by FAND (which reverses XOR-AA on load). Full
    verification still requires DOSBox.
    """
    global args_format_is_x, args_format_is_xor_aa
    saved_x, saved_aa = args_format_is_x, args_format_is_xor_aa
    args_format_is_x = True
    args_format_is_xor_aa = True
    try:
        licnr = struct.unpack_from("<H", ttt, 458)[0]
        cat = rdbparse.parse_catalog(rdb)
        _, reclen, records = rdbparse.parse_rdb(rdb)
        buf = bytearray(512)  # page0 placeholder
        new_positions = []
        for entry in cat:
            pos = entry["txtpos"] - licnr
            raw = _reassemble_tfile_record(ttt, pos) if 512 <= pos < len(ttt) else None
            if raw is None:
                new_positions.append(None)
                continue
            length = struct.unpack_from("<H", ttt, pos)[0]
            dec = None
            for c in _record_candidates(raw, length):
                if _looks_like_text(c):
                    dec = c
                    break
            # Source-text records are re-stored XOR-AA (FAND reverses Code() on
            # load). Undecodable / binary members are kept verbatim so they
            # round-trip byte-for-byte and FAND sees exactly the original bytes.
            payload = decode_xor_aa(dec) if dec is not None else raw
            start = _write_tfile_record(buf, payload)
            new_positions.append(start)
        if len(buf) % 512:
            buf.extend(b"\x00" * (512 - len(buf) % 512))
        page0 = _build_tfile_page0(0, len(buf), 0)
        buf[0:512] = page0
        new_ttt = bytes(buf)
        # Rebuild the .rdb with updated TxtPos fields (LicNr in new .ttt is 0).
        new_rdb = bytearray(rdb[:6])
        for i, entry in enumerate(cat):
            if i >= len(records):
                break
            rec = bytearray(records[i])
            np_ = new_positions[i]
            # Unrebuildable entries get TxtPos=0 so the loader (and our own
            # decoder) skips them, exactly mirroring the original .rdb whose
            # invalid positions were skipped by iter_catalog_records.
            struct.pack_into("<I", rec, 20, np_ if np_ is not None else 0)
            new_rdb += rec
        return new_ttt, bytes(new_rdb)
    finally:
        args_format_is_x, args_format_is_xor_aa = saved_x, saved_aa


def _record_candidates(raw: bytes, length: int) -> "list[bytes]":
    """Decode one reassembled LongStr ``raw`` with every known transform.

    Order matches what FAND does on load: first the plain XOR 0xAA ``Code()``
    transform, then the XEncode reverse (decode_x_segment), then the raw bytes
    (unencoded plaintext records). Trying XOR-AA first is essential so that a
    record already stored XOR-AA (e.g. from ``wtfile``) is not mis-read as an
    XEncode segment. Callers pick whichever yields readable source text.
    """
    cands = []
    cands.append(decode_xor_aa(raw))
    try:
        cands.append(decode_x_segment(struct.pack("<H", length) + raw))
    except DecodeError:
        pass
    cands.append(raw)
    return cands


def _decode_segment_best(segment: bytes) -> "bytes | None":
    """Try XEncode, then XOR-AA, then verbatim; return the first that reads as text.

    Some FAND exports store a segment unencoded (plaintext). Returning the raw
    bytes when they already look like source text recovers those segments
    instead of discarding them.
    """
    candidates = []
    if args_format_is_x:
        try:
            candidates.append(decode_x_segment(segment))
        except DecodeError:
            pass
    if args_format_is_xor_aa:
        candidates.append(decode_xor_aa(segment))
    candidates.append(segment)
    for cand in candidates:
        if _looks_like_text(cand):
            return cand
    return None


args_format_is_x = False
args_format_is_xor_aa = False
args_randseed = 0


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="encoded file (segment or full file)")
    parser.add_argument("output", type=Path, help="decoded output file")
    parser.add_argument(
        "--format",
        choices=("x", "xor-aa", "both"),
        default="both",
        help=(
            "input format for each segment (default: both). "
            "'x' decodes the XEncode compressed LongStr used by licensed/rotated "
            "builds (CodingCRdb with Rotate=true). "
            "'xor-aa' reverses the plain XOR 0xAA Code() transform used by "
            "password-protected ('nevratně zaheslovaná') builds "
            "(CodingCRdb with Rotate=false). "
            "'both' tries each record with both transforms and keeps the one that "
            "yields readable text (used with --mode tfile)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("segment", "full", "tfile", "wtfile", "rtfile", "tcat"),
        default="segment",
        help=(
            "decoding mode (default: segment). "
            "'segment' treats the whole input file as one encoded LongStr segment "
            "and decodes it at once. "
            "'full' scans the file sequentially, decoding every consecutive "
            "LongStr segment (2-byte little-endian length header) one by one; "
            "segments that fail to decode are kept as raw bytes and the results "
            "are joined with a newline. "
            "'tfile' treats the input as a FAND TFile container (512-byte pages): "
            "it reassembles each LongStr record across pages and decodes it with "
            "the XEncode and/or XOR 0xAA transforms, keeping readable source text. "
            "'tcat' (catalog-driven) requires --rdb: it decodes the .ttt using the "
            "exact record offsets from the paired .rdb member catalog (TxtPos - "
            "LicNr), which is exact and free of false positives. "
            "'wtfile' re-emits the .ttt as a loadable unencrypted TFile. "
            "'rtfile' dumps the raw (still-encoded) LongStr records for inspection."
        ),
    )
    parser.add_argument(
        "--rdb",
        type=Path,
        default=None,
        help=(
            "paired .rdb member catalog, required by --mode tcat and used by "
            "--mode wtfile to regenerate a consistent .rdb. The catalog supplies "
            "the exact source-text offsets (TxtPos) for each record."
        ),
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=None,
        help=(
            "with --mode tcat, write each member chapter to its own file inside "
            "this directory (NNN_name.txt) instead of (or in addition to) the "
            "single combined output file."
        ),
    )
    parser.add_argument(
        "--rdb-out",
        type=Path,
        default=None,
        help=(
            "with --mode wtfile --rdb, path for the regenerated .rdb catalog. "
            "Defaults to the input .ttt stem with a .rdb extension."
        ),
    )
    args = parser.parse_args()

    global args_format_is_x, args_format_is_xor_aa
    args_format_is_x = args.format in ("x", "both")
    args_format_is_xor_aa = args.format in ("xor-aa", "both")

    data = args.input.read_bytes()
    if args.mode == "tfile":
        decoded = decode_tfile(data)
    elif args.mode == "rtfile":
        # Extract raw (encoded) LongStr records and write one per line (hex+text).
        recs = extract_tfile_records(data)
        parts = []
        for i, r in enumerate(recs):
            parts.append(f"--- record {i} ({len(r)} bytes) ---".encode("utf-8"))
            parts.append(r)
            parts.append(b"")
        decoded = b"\n".join(parts)
    elif args.mode == "wtfile":
        if args.rdb is not None:
            # Cataloged rebuild: emit a new .ttt AND a matching new .rdb.
            rdb_data = args.rdb.read_bytes()
            new_ttt, new_rdb = rebuild_tfile_cataloged(data, rdb_data)
            args.output.write_bytes(new_ttt)
            rdb_out = args.rdb_out or args.output.with_suffix(".rdb")
            Path(rdb_out).write_bytes(new_rdb)
            return 0
        # Fallback: blind re-emit as a loadable, unencrypted .ttt.
        decoded = rebuild_tfile(data)
    elif args.mode == "tcat":
        if args.rdb is None:
            parser.error("--mode tcat requires --rdb <catalog.rdb>")
        rdb_data = args.rdb.read_bytes()
        if args.outdir is not None:
            write_chapters(data, rdb_data, args.outdir)
        decoded = decode_tfile_cataloged(data, rdb_data)
    elif args.mode == "segment":
        # Treat the entire file as a single encoded segment; fall back to raw
        decoded = _decode_segment_best(data)
        if decoded is None:
            decoded = data
    else:
        # Full scan: decode each LongStr segment in sequence
        decoded_parts = []
        offset = 0
        total_len = len(data)
        while offset + 2 <= total_len:
            # Read the declared length of the next segment
            seg_len = struct.unpack_from("<H", data, offset)[0]
            seg_end = offset + seg_len + 2  # include the 2-byte length field
            if seg_end > total_len:
                # Not enough data left; treat the rest as raw and break
                decoded_parts.append(data[offset:])
                break
            segment = data[offset:seg_end]
            decoded_seg = _decode_segment_best(segment)
            if decoded_seg is not None:
                decoded_parts.append(decoded_seg)
            else:
                # If decoding fails, fall back to raw bytes for this segment
                decoded_parts.append(segment)
            offset = seg_end
        # Append any leftover bytes that don't start a segment
        if offset < total_len:
            decoded_parts.append(data[offset:])
        decoded = b"\n".join(decoded_parts)
    args.output.write_bytes(decoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

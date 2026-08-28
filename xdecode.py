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
    then reverses both the XEncode (``--format x``) and XOR-AA (``--format
    xor-aa``) transforms, keeping whatever yields readable FAND source text.
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
        for dec in candidates:
            if _looks_like_text(dec) and dec not in seen:
                seen.add(dec)
                out += dec
                out += b"\n"
    return bytes(out)


args_format_is_x = False
args_format_is_xor_aa = False


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
        choices=("segment", "full", "tfile"),
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
            "the XEncode and/or XOR 0xAA transforms, keeping readable source text"
        ),
    )
    args = parser.parse_args()

    global args_format_is_x, args_format_is_xor_aa
    args_format_is_x = args.format in ("x", "both")
    args_format_is_xor_aa = args.format in ("xor-aa", "both")

    data = args.input.read_bytes()
    if args.mode == "tfile":
        decoded = decode_tfile(data)
    elif args.mode == "segment":
        # Treat the entire file as a single encoded segment
        decoded = decode_x_segment(data) if args.format == "x" else decode_xor_aa(data)
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
            decoded_seg = None
            try:
                if args_format_is_x:
                    decoded_seg = decode_x_segment(segment)
                if decoded_seg is None and args_format_is_xor_aa:
                    decoded_seg = decode_xor_aa(segment)
            except DecodeError:
                decoded_seg = None
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

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
            output.append(segment[source] ^ mask)
            source += 1
            mask = _rol8(mask, 1)

        flag_mask <<= 1
        if flag_mask > 0x80:
            flag_mask = 0

    return bytes(output[2:])


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="encoded file (segment or full file)")
    parser.add_argument("output", type=Path, help="decoded output file")
    parser.add_argument(
        "--format",
        choices=("x", "xor-aa"),
        default="x",
        help=(
            "input format for each segment (default: x). "
            "'x' decodes the XEncode compressed LongStr used by licensed/rotated "
            "builds (CodingCRdb with Rotate=true). "
            "'xor-aa' reverses the plain XOR 0xAA Code() transform used by "
            "password-protected ('nevratně zaheslovaná') builds "
            "(CodingCRdb with Rotate=false)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("segment", "full"),
        default="segment",
        help=(
            "decoding mode (default: segment). "
            "'segment' treats the whole input file as one encoded LongStr segment "
            "and decodes it at once. "
            "'full' scans the file sequentially, decoding every consecutive "
            "LongStr segment (2-byte little-endian length header) one by one; "
            "segments that fail to decode are kept as raw bytes and the results "
            "are joined with a newline"
        ),
    )
    args = parser.parse_args()

    data = args.input.read_bytes()
    if args.mode == "segment":
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
            try:
                decoded_seg = decode_x_segment(segment) if args.format == "x" else decode_xor_aa(segment)
                decoded_parts.append(decoded_seg)
            except DecodeError:
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

"""Decode FAND text segments produced by Code and XEncode.

The X format is the in-memory LongStr representation written by EXPIMP.PAS:
- uint16 little-endian length at offset 0
- encoded payload and random displacement padding
- time byte and XOR-masked displacement trailer
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
    parser.add_argument("input", type=Path, help="encoded segment file")
    parser.add_argument("output", type=Path, help="decoded output file")
    parser.add_argument(
        "--format",
        choices=("x", "xor-aa"),
        default="x",
        help="input format (default: x)",
    )
    args = parser.parse_args()

    encoded = args.input.read_bytes()
    decoded = decode_x_segment(encoded) if args.format == "x" else decode_xor_aa(encoded)
    args.output.write_bytes(decoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

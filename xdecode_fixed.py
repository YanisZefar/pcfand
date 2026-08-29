import struct

def _rol8(value, count):
    count &= 7
    return ((value << count) | (value >> (8 - count))) & 0xFF if count else value

class DecodeError(ValueError):
    pass

def decode_x_segment(segment: bytes) -> bytes:
    """Decode XEncode LongStr segment. segment = 2-byte LL + payload (payload must
    include the trailing RMask-seed byte + 2-byte masked-displacement trailer)."""
    if len(segment) < 4:
        raise DecodeError("too short")
    encoded_length = struct.unpack_from("<H", segment)[0]
    if encoded_length == 0:
        return b""
    if encoded_length < 3:
        raise DecodeError(f"invalid length {encoded_length}")
    if len(segment) < encoded_length + 2:
        raise DecodeError(f"truncated: need {encoded_length+2}, got {len(segment)}")

    trailer_time = segment[encoded_length - 1]
    masked_displacement = struct.unpack_from("<H", segment, encoded_length)[0]
    displacement = masked_displacement ^ 0xCCCC
    payload_start = 2 + displacement
    payload_end = encoded_length - 1
    if payload_start < 2 or payload_start > payload_end:
        raise DecodeError(f"bad displacement: start={payload_start} end={payload_end}")

    mask = _rol8(0x9C, trailer_time & 3)
    source = payload_start
    # output buffer mirrors the Pascal in-place buffer coordinates: position 0,1
    # are the (discarded) LL header slot; real output starts at position 2.
    output = bytearray(b"\x00\x00")
    flag_bits = 0
    flag_mask = 0

    while source < payload_end:
        if flag_mask == 0:
            flag_bits = segment[source]
            source += 1
            flag_mask = 0x01

        if flag_bits & flag_mask:
            if source + 3 > payload_end + 1:  # length + 2-byte offset must fit
                raise DecodeError("truncated back-reference")
            length = segment[source]
            offset = struct.unpack_from("<H", segment, source + 1)[0]
            source += 3
            if length == 0 or offset < 2:
                raise DecodeError("invalid back-reference")
            for _ in range(length):
                if offset >= len(output):
                    raise DecodeError("back-reference out of range")
                output.append(output[offset])
                offset += 1
        else:
            if source >= payload_end:
                raise DecodeError("truncated literal")
            mask = _rol8(mask, 1)
            output.append(segment[source] ^ mask)
            source += 1

        flag_mask <<= 1
        if flag_mask > 0x80:
            flag_mask = 0

    return bytes(output[2:])


def decode_xor_aa(data: bytes) -> bytes:
    return bytes(b ^ 0xAA for b in data)

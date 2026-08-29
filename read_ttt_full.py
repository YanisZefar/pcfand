import struct
from xdecode_fixed import decode_x_segment, DecodeError

def read_t00_multi(ttt, pos):
    """Read a possibly multi-page T00 LongStr starting at byte pos.
    Returns the raw (still XEncode-encoded) payload bytes, matching what
    TFile.Read would leave in S^.A before XDecode is applied, i.e. exactly
    `length` bytes where length is read from the first page's 2-byte prefix.
    Handles the RdWr continuation scheme: each page holds up to
    (page_end-current) bytes, reserving the last 4 bytes of the page for a
    'next page' pointer when content continues beyond this page.
    """
    if pos < 512 or pos+2 > len(ttt):
        raise DecodeError(f"pos {pos} out of range")
    length = ttt[pos] | (ttt[pos+1] << 8)
    if length == 0:
        return b""
    if length > 65000:
        raise DecodeError(f"implausible length {length}")
    result = bytearray()
    current = pos + 2
    remaining = length
    while remaining:
        page_end = ((current // 512) + 1) * 512
        available = page_end - current
        if remaining <= available:
            if current + remaining > len(ttt):
                raise DecodeError("truncated (final segment)")
            result.extend(ttt[current:current+remaining])
            remaining = 0
        else:
            chunk = available - 4
            if chunk <= 0 or current+chunk+4 > len(ttt):
                raise DecodeError("bad continuation layout")
            result.extend(ttt[current:current+chunk])
            remaining -= chunk
            next_page = page_end - 4
            current = struct.unpack_from('<I', ttt, next_page)[0]
            if current < 512 or current >= len(ttt):
                raise DecodeError(f"bad next-page pointer {current}")
    return bytes(result)


def read_and_decode(ttt, pos):
    raw = read_t00_multi(ttt, pos)
    if not raw:
        return b""
    seg = struct.pack('<H', len(raw)) + raw
    return decode_x_segment(seg)

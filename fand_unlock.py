import argparse
import csv
import os
import re
import shutil
import struct
import sys

import xdecode

PAGE = 512
RDB_HDR = 6
CAT_RECLEN = 24
NAME_OFF = 7
NAME_LEN = 12
TXTPOS_OFF = 20
LICNR_OFF = 458
CP852 = "cp852"

TABF = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 5, 5, 6, 6, 6, 7, 7, 8, 8]
FIELD_RE = re.compile(
    rb"([^\s:;]+)\s*:\s*([ANFRDBT])\s*"
    rb"(?:,\s*(?:(\d+(?:\.\d+)?)|'([^']*)'))?"
    rb"[^;]*"
)
# Data files only (index files .X00 are excluded by the caller).
DATA_EXTS = (".000", ".001", ".dbf", ".db")


def read_licnr(ttt):
    if len(ttt) <= LICNR_OFF + 2:
        return 0
    return struct.unpack_from("<H", ttt, LICNR_OFF)[0]


def parse_rdb(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < RDB_HDR + CAT_RECLEN:
        return None
    nrecs = struct.unpack_from("<I", data, 0)[0]
    reclen = struct.unpack_from("<H", data, 4)[0]
    if reclen != CAT_RECLEN:
        return {"nrecs": nrecs, "reclen": reclen, "catalog": False, "records": []}
    recs = []
    for i in range(nrecs):
        base = RDB_HDR + i * reclen
        chunk = data[base:base + reclen]
        if len(chunk) < CAT_RECLEN:
            break
        typ = chunk[0]
        name = chunk[NAME_OFF:NAME_OFF + NAME_LEN].split(b"\x00")[0]
        name = name.decode(CP852, "replace").rstrip()
        txtpos = struct.unpack_from("<I", chunk, TXTPOS_OFF)[0]
        recs.append({"typ": typ, "name": name, "txtpos": txtpos})
    return {"nrecs": nrecs, "reclen": reclen, "catalog": True, "records": recs}


def decode_chapter(ttt, pos):
    if pos < PAGE or pos + 2 > len(ttt):
        return None
    length = struct.unpack_from("<H", ttt, pos)[0]
    raw = xdecode._reassemble_tfile_record(ttt, pos)
    if raw is None or len(raw) < 2:
        return None
    seg = struct.pack("<H", length) + raw
    try:
        d = xdecode.decode_x_segment(seg)
        if xdecode._looks_like_text(d):
            return d
    except Exception:
        pass
    if xdecode._looks_like_text(raw):
        return raw
    try:
        return xdecode.decode_x_segment(seg)
    except Exception:
        return raw


def parse_schema_fields(text):
    """Parse FAND field declarations into field dicts with byte offsets.

    Handles every storage type (A/N/F/R/D/B/T), typed-without-length fields
    (``Datum :D,...``, ``Blokovan :B;``) and mask-only fields (``Zázn :A,'$'``).
    ``nbytes`` is the on-disk size; ``off`` is the offset from the start of the
    fields region (i.e. after the leading 1-byte record flag).
    """
    fields = []
    off = 0
    for m in FIELD_RE.finditer(text or b""):
        name = m.group(1).decode(CP852, "replace")
        ftype = m.group(2).decode("ascii")
        length = m.group(3).decode("ascii") if m.group(3) else None
        L = M = 0
        if length:
            L = int(length.split(".")[0])
            M = int(length.split(".")[1]) if "." in length else 0
        if ftype in ("R", "D"):
            nbytes = 6
        elif ftype == "B":
            nbytes = 1
        elif ftype == "A":
            nbytes = L if length else 1
        elif ftype == "N":
            nbytes = (L + 1) // 2 if L else 1
        elif ftype == "F":
            nbytes = TABF[min(L + M, len(TABF) - 1)] if L else 1
        elif ftype == "T":
            nbytes = 4
        else:
            nbytes = L or 1
        fields.append({"name": name, "type": ftype, "L": L, "M": M,
                       "nbytes": nbytes, "off": off})
        off += nbytes
    return fields


def xorAA(b):
    return bytes(c ^ 0xAA for c in b)


EMPTY_FILLS = frozenset((0x00, 0x20, 0xFF))


def _is_fill(b):
    return len(b) > 0 and all(c in EMPTY_FILLS for c in b)


def _is_numeric_fill(b):
    """Empty FAND number: all 0x00 (N fields) or the 0xFF-fill sentinel used by
    F/R/D fields (0xFF bytes, last byte's low nibble is a sign/0xF)."""
    if not b:
        return True
    if all(c == 0x00 for c in b) or all(c == 0xFF for c in b):
        return True
    for i, c in enumerate(b):
        if i < len(b) - 1:
            if c != 0xFF:
                return False
        else:
            if c == 0xFF:
                continue
            if (c & 0xF0) != 0xF0:
                return False
            if (c & 0x0F) not in (0xA, 0xB, 0xC, 0xD, 0xE, 0xF):
                return False
    return True


def _bcd_to_int(b):
    """Unpack packed-BCD (2 digits/byte). The last byte's low nibble is a digit
    when 0-9, otherwise a sign nibble (0xB/0xD = negative)."""
    digits = []
    sign = 1
    for i, byte in enumerate(b):
        hi = (byte >> 4) & 0xF
        lo = byte & 0xF
        if i == len(b) - 1:
            digits.append(hi)
            if lo <= 9:
                digits.append(lo)
            elif lo in (0xB, 0xD):
                sign = -1
        else:
            digits.append(hi)
            digits.append(lo)
    s = "".join(str(d) for d in digits)
    if not s:
        return 0
    return sign * int(s)


def _tp_real(b):
    """Decode a 6-byte Turbo Pascal REAL48 into a Python float.
    Byte 0 = exponent (biased by 129); bytes 1-5 = 40-bit mantissa with the
    sign in the high bit of byte 1; the implicit leading 1 is at bit 39."""
    if len(b) != 6:
        return 0.0
    e = b[0]
    if e == 0:
        return 0.0
    exp = e - 129
    sign = -1.0 if (b[1] & 0x80) else 1.0
    mant = int.from_bytes(b[1:6], "big") & 0x7FFFFFFFFF
    return sign * (1.0 + mant / 2.0 ** 39) * 2.0 ** exp


_NODAYINMONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _olympyear(y):
    return (y % 4 == 0) and ((y % 100 != 0) or (y % 400 == 0))


def _olympyears(y):
    if y < 3:
        return 0
    y -= 1
    return y // 4 - y // 100 + y // 400


def fand_serial_to_date(R):
    """Convert a FAND date serial (days since year 1, per COMMON.PAS SplitDate)
    to a (Y, M, D) tuple."""
    l = int(R)
    if l == 0:
        return None
    y = l // 365
    y += 1
    l = l % 365
    while l <= _olympyears(y):
        y -= 1
        l += 365
    l -= _olympyears(y)
    for j in range(1, 13):
        i = _NODAYINMONTH[j - 1]
        if j == 2 and _olympyear(y):
            i += 1
        if i >= l:
            break
        l -= i
    return (y, j, l)


def _decode_A(b):
    b = xorAA(b)
    if _is_fill(b):
        return ""
    s = b.replace(b"\xff", b"").split(b"\x00")[0]
    return s.decode(CP852, "replace").rstrip()


# FAND epoch for integer-mode ('8') date fields: stored = RDate_serial - FIRSTDATE.
# FirstDate = 6.97248E+5 (RECACC.PAS:163) = FAND serial of 1910-01-01.
FIRSTDATE = 697248


def _decode_field(b, f, file_type=None):
    t = f["type"]
    if t == "A":
        return _decode_A(b)
    if t == "B":
        return 0 if b[0] in (0, 0xFF) else 1
    if t == "N":
        if _is_numeric_fill(b):
            return ""
        return _bcd_to_int(b)
    if t == "F":
        if _is_numeric_fill(b):
            return ""
        v = int.from_bytes(b, "big", signed=True)
        if f["M"]:
            v = v / (10 ** f["M"])
        return v
    if t == "R":
        if _is_numeric_fill(b):
            return ""
        return _tp_real(b)
    if t == "D":
        return _decode_D(b, file_type)
    return _decode_A(b)


def _decode_D(b, file_type):
    # '8' režim (CFile^.Typ='8'): 2B signed int = RDate_serial - FIRSTDATE.
    if file_type in (0x38, "8"):
        v = struct.unpack("<h", (b + b"\x00\x00")[:2])[0]
        if v == 0:
            return ""
        ymd = fand_serial_to_date(v + FIRSTDATE)
        if ymd and 1900 <= ymd[0] <= 2100:
            return f"{ymd[0]:04d}-{ymd[1]:02d}-{ymd[2]:02d}"
        return ""
    # 'D' režim (CFile^.Typ='D'): 8-znakový řetězec 'YYYYMMDD'.
    if file_type in (0x44, "D"):
        try:
            s = b.rstrip(b" \x00\xff").decode(CP852)
        except Exception:
            s = ""
        if len(s) >= 8 and s[:8].isdigit():
            y, m, d = int(s[:4]), int(s[4:6]), int(s[6:8])
            if 1900 <= y <= 2100:
                return f"{y:04d}-{m:02d}-{d:02d}"
        return ""
    # výchozí režim: REAL48 přímo = RDate_serial (dny od 1.1.0001).
    if _is_numeric_fill(b):
        return ""
    try:
        val = _tp_real(b)
    except Exception:
        return ""
    if val < 1:
        return ""
    ymd = fand_serial_to_date(val)
    if ymd and 1900 <= ymd[0] <= 2100:
        return f"{ymd[0]:04d}-{ymd[1]:02d}-{ymd[2]:02d}"
    return ""


def _read_t00(t00, phys):
    if t00 is None:
        return None
    if phys < 512 or phys + 2 > len(t00):
        return None
    raw = xdecode._reassemble_tfile_record(t00, phys)
    if not raw:
        return None
    s = raw.split(b"\x00")[0].decode(CP852, "replace").rstrip()
    if not s or not any(0x20 <= ord(c) <= 0x7E or 0x80 <= ord(c) <= 0xFF for c in s):
        return None
    return s


def _decode_T(pb, t00):
    ptr = int.from_bytes(pb, "little")
    if ptr in (0, 0xAAAAAAAA):
        return ""
    for phys in (ptr, ptr + 384):
        txt = _read_t00(t00, phys)
        if txt:
            return txt
    return ""


def convert_data_file(path, fields, t00_path=None, file_type=None,
                     include_deleted=False):
    """Decode a FAND data file into rows.

    Layout: 6-byte plaintext header (signed NRecs@0, RecLen@4) + a flat run of
    fixed-length records. Each record has a 1-byte flag (0=active, 1=deleted for
    type 'X' files) then the fields. The whole record region is stored in
    plaintext (the T pointers too). Field offsets are relative to the start of
    the record (including the flag), so the first field lives at offset 1.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) < 6:
        return None
    nrecs = abs(struct.unpack_from("<i", raw, 0)[0])
    reclen = struct.unpack_from("<H", raw, 4)[0]
    if reclen <= 0 or nrecs <= 0 or nrecs > 2000000:
        return None
    if not fields:
        return None
    expected = sum(f["nbytes"] for f in fields) + 1
    has_flag = (reclen == expected)
    if not has_flag and reclen != expected - 1:
        return None
    data = raw[6:]
    rawdata = raw[6:]
    t00 = None
    if t00_path and os.path.exists(t00_path):
        with open(t00_path, "rb") as fh:
            t00 = fh.read()
    rows = []
    start = 1 if has_flag else 0
    for i in range(nrecs):
        base = i * reclen
        rec = data[base:base + reclen]
        if len(rec) < reclen:
            break
        if has_flag and rec[0] != 0 and not include_deleted:
            continue
        row = []
        for f in fields:
            o = start + f["off"]
            if f["type"] == "T":
                pb = rawdata[base + o:base + o + f["nbytes"]]
                row.append(_decode_T(pb, t00))
            else:
                b = rec[o:o + f["nbytes"]]
                row.append(_decode_field(b, f, file_type))
        rows.append(row)
    return rows


def _list_files(folder):
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    return [os.path.join(folder, n) for n in sorted(names)
            if os.path.isfile(os.path.join(folder, n))]


def find_pairs(folder):
    files = _list_files(folder)
    pairs = []
    for path in files:
        if os.path.splitext(path)[1].lower() != ".rdb":
            continue
        base = os.path.splitext(os.path.basename(path))[0]
        ttt = None
        for cand in files:
            if os.path.basename(cand).lower() == base.lower() + ".ttt":
                ttt = cand
                break
        pairs.append((path, ttt))
    return pairs


def find_standalone_tfiles(folder, paired_ttts):
    out = []
    for path in _list_files(folder):
        if os.path.splitext(path)[1].lower() not in (".ttt", ".t00"):
            continue
        if os.path.abspath(path) in paired_ttts:
            continue
        out.append(path)
    return out


def _schema_key(name):
    k = name.lower()
    if k.startswith("f"):
        k = k[1:]
    return k.replace(".x", "")


def export_data_tables(folder, schema_by_key, file_type_by_key, out_dir,
                      include_deleted=False):
    """Emit one CSV per FAND data file (columns = schema, rows = .000 + .T00)."""
    tables = []
    seen = set()
    for path in _list_files(folder):
        ext = os.path.splitext(path)[1].lower()
        if ext not in DATA_EXTS or ext == ".x00":
            continue
        base = os.path.splitext(os.path.basename(path))[0]
        stem = base.lower()
        skey = stem[1:] if stem.startswith("f") else stem
        fields = schema_by_key.get(skey) or schema_by_key.get(stem)
        if not fields or skey in seen:
            continue
        seen.add(skey)
        t00 = None
        for cand in _list_files(folder):
            cand_base = os.path.basename(os.path.splitext(cand)[0]).lower()
            if cand_base == base.lower() and \
               os.path.splitext(cand)[1].lower() == ".t00":
                t00 = cand
                break
        rows = convert_data_file(path, fields, t00,
                                file_type=file_type_by_key.get(skey),
                                include_deleted=include_deleted)
        if not rows:
            continue
        csv_name = base + ".csv"
        csv_path = os.path.join(out_dir, csv_name)
        with open(csv_path, "w", encoding="utf-8", newline="") as ch:
            w = csv.writer(ch)
            w.writerow([f["name"] for f in fields])
            w.writerows(rows)
        tables.append((csv_name, len(rows), csv_path))
    return tables


def process(folder, out_root, include_deleted=False):
    pairs = find_pairs(folder)
    paired_ttts = {os.path.abspath(t) for _, t in pairs if t}
    standalone = find_standalone_tfiles(folder, paired_ttts)

    out_dir = out_root
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    dec_dir = os.path.join(out_dir, "decoded")
    os.makedirs(dec_dir, exist_ok=True)

    katalog_rows = []
    schema_rows = []
    cli_lines = []
    decoded_count = 0
    data_tables = []
    schema_by_key = {}
    file_type_by_key = {}

    for rdb, ttt in pairs:
        app = os.path.splitext(os.path.basename(rdb))[0]
        info = parse_rdb(rdb)
        cli_lines.append(f"== {app} ==")
        if not info:
            cli_lines.append("  (neplatny .rdb)")
            continue
        if not info["catalog"]:
            cli_lines.append(
                f"  datafile: NRecs={info['nrecs']} RecLen={info['reclen']} "
                f"(zadny katalog)")
            continue
        app_dec_dir = os.path.join(dec_dir, app)
        os.makedirs(app_dec_dir, exist_ok=True)
        licnr = 0
        ttt_bytes = None
        if ttt:
            with open(ttt, "rb") as fh:
                ttt_bytes = fh.read()
            licnr = read_licnr(ttt_bytes)
        cli_lines.append(
            f"  katalog: {len(info['records'])} objektu, LicNr={licnr}")
        for rec in info["records"]:
            name = rec["name"]
            txtpos = rec["txtpos"]
            pos = txtpos - licnr if txtpos else 0
            decoded = None
            if ttt_bytes and pos >= PAGE:
                decoded = decode_chapter(ttt_bytes, pos)
            ok = bool(decoded)
            if ok:
                decoded_count += 1
                dpath = os.path.join(app_dec_dir, f"{name}.txt")
                with open(dpath, "w", encoding="utf-8") as dh:
                    dh.write(decoded.decode(CP852, "replace"))
                fields = parse_schema_fields(decoded)
                key = _schema_key(name)
                if key not in schema_by_key:
                    schema_by_key[key] = fields
                    file_type_by_key[key] = rec["typ"]
                for fi, f in enumerate(fields, 1):
                    schema_rows.append([
                        app, name, fi, f["name"], f["type"],
                        f["L"] if not f["M"] else f"{f['L']}.{f['M']}"])
            katalog_rows.append([
                app, rec["typ"], name, txtpos, pos if txtpos else "",
                "ano" if ok else "ne", len(decoded) if ok else 0])
            cli_lines.append(
                f"  [{rec['typ']:#04x}] {name:16} "
                f"{'OK' if ok else 'CHYBA'}"
                f"{(' -> ' + str(len(decoded)) + 'B') if ok else ''}")

    data_tables = export_data_tables(folder, schema_by_key, file_type_by_key,
                                      out_dir, include_deleted=include_deleted)

    standalone_decoded = 0
    for path in standalone:
        with open(path, "rb") as fh:
            data = fh.read()
        text = xdecode.decode_tfile(data)
        if text:
            standalone_decoded += 1
            base = os.path.splitext(os.path.basename(path))[0]
            with open(os.path.join(dec_dir, f"{base}.txt"), "w", encoding="utf-8") as dh:
                dh.write(text.decode(CP852, "replace"))

    with open(os.path.join(out_dir, "katalog.csv"), "w", encoding="utf-8", newline="") as ch:
        w = csv.writer(ch)
        w.writerow(["aplikace", "typ", "nazev", "txtpos", "pozice", "dekodovano", "delka"])
        w.writerows(katalog_rows)
    with open(os.path.join(out_dir, "schemas.csv"), "w", encoding="utf-8", newline="") as ch:
        w = csv.writer(ch)
        w.writerow(["aplikace", "objekt", "poradi", "pole", "typ", "delka"])
        w.writerows(schema_rows)

    write_report(out_dir, folder, pairs, katalog_rows, schema_rows,
                 decoded_count, standalone_decoded, data_tables)

    print(f"Vystup: {out_dir}")
    print(f"Dekodovano kapitol: {decoded_count} | schémat: {len(schema_rows)} "
          f"| datovych tabulek: {len(data_tables)} |"
          f" standalone .ttt/.t00: {standalone_decoded}")
    for line in cli_lines:
        print(line)
    return out_dir


def write_report(out_dir, folder, pairs, katalog_rows, schema_rows,
                 decoded_count, standalone_decoded, data_tables):
    md = []
    md.append("# Zprava o dekodovani FAND aplikace\n")
    md.append(f"**Slozka:** `{folder}`  \n")
    md.append(f"**Dekodovano kapitol:** {decoded_count}  \n")
    md.append(f"**Extrakovano poli schématu:** {len(schema_rows)}  \n")
    md.append(f"**Datovych tabulek (CSV):** {len(data_tables)}  \n")
    md.append(f"**Samostatnych .ttt/.t00:** {standalone_decoded}\n")
    md.append("\n## Poznamky\n")
    md.append("- Znakova sada zdroje je CP852 (Kamenicky); dekodovany text je "
              "ulozen v UTF-8. Binary .rdb/.ttt zachovavaji pusodni bajty.\n")
    md.append("- Katalog .rdb: 6B hlavicka (NRecs u32, RecLen u16) + 24B "
              "zaznamy (Typ @0, Nazev @7, TxtPos u32 @20). TxtPos - LicNr "
              "(v .ttt @458) = pozice textu.\n")
    md.append("- Re-kodovany NEZASIFROVANY .ttt zapisovac je odlozen "
              "(viz nize); vystupem je zaruka citelny plain-text export.\n")
    md.append("\n## Katalog\n")
    md.append("| aplikace | typ | nazev | txtpos | pozice | dekodovano | delka |")
    md.append("|---|---|---|---|---|---|---|")
    for r in katalog_rows:
        md.append("| " + " | ".join(str(x) for x in r) + " |")
    md.append("\n## Schmata (ukazka poli)\n")
    if schema_rows:
        md.append("| aplikace | objekt | poradi | pole | typ | delka |")
        md.append("|---|---|---|---|---|---|")
        for r in schema_rows[:200]:
            md.append("| " + " | ".join(str(x) for x in r) + " |")
        if len(schema_rows) > 200:
            md.append(f"\n_...a dalsich {len(schema_rows) - 200} poli._")
    else:
        md.append("_Zadna pole nebyla rozpoznana._")
    md.append("\n## Datove tabulky\n")
    if data_tables:
        md.append("| objekt | radku | soubor |")
        md.append("|---|---|---|")
        for name, n, path in data_tables:
            md.append(f"| {name} | {n} | `{os.path.basename(path)}` |")
    else:
        md.append("_Zadne datove soubory (.X/.000/.dbf) nebyly nalezeny - "
                  "konverze radku ceka na dodani dat._\n")
    md.append("\n## Format datovych souboru (.000 / .T00)\n")
    md.append("- Datovy soubor `.000` ma 6B hlavicku (NRecs i32 - abs, RecLen u16) "
              "a pak **plain-text** oblast: kazdy zaznam je 1B flag (0=aktivni, "
              "1=smazany) + pole fixni delky dle schématu. RecLen = suma NBytes + 1.\n")
    md.append("- Pole typu `A` (text) jsou v `.000` ulozena **XOR-AA** zašifrovaně "
              "(procedura `Code` v ACCESS.PAS) a dekoduji se pres xorAA + CP852.\n")
    md.append("- Pole typu `T` (odkaz) jsou 4B ukazatel do `.T00` (TFile); "
              "ctou se pres `_reassemble_tfile_record`. Některé vzácné velké "
              "ukazatele (>offset souboru) se zatim neresi a zustavaji prazdne.\n")
    md.append("- `F` = 6B resp. `TabF[L+M]` big-endian se znamenkem / 10^M; "
              "`N` = BCD; `R` = 6B TP REAL48.\n")
    md.append("- `D` (datum) ma tri režimy podle typu souboru v katalogu "
              "(RECACC.PAS): vychozi = 6B REAL48 s RDate serialem (dny od "
              "1.1.0001 pres `SplitDate`); typ '8' = 2B signed int + `FirstDate` "
              "(697248 = 1.1.1910); typ 'D' = 8 znaku `YYYYMMDD`. Vše omezeno "
              "na roky 1900-2100.\n")
    md.append("\n## Omezeni / dalsi kroky\n")
    md.append("1. Zapis loadovatelneho nezasifrovaneho .ttt (TFile) vyžaduje "
              "implementaci zapisovace a overeni v DOSBoxu/FANDu; zatim je "
              "vystupem zaruka citelny plain-text export.\n")
    md.append("2. Konverze datovych souboru do CSV je heuristicka: pole se "
              "ctou jako fixni delky v CP852. Binarni typy FAND (F=float, "
              "N=cislo, D=datum, B=logika, R=float) vyžaduji typove dekodery - "
              "bez nich jsou tabulky s binarnimi poli vyrazeny branou na "
              "platnost (viz `datovych tabulek`).\n")
    md.append("3. Mapovani katalogoveho jmena na datovy soubor je zjednodusene "
              "(kmen jmena, ignoruje FAND prefix/typ); presne mapovani dle "
              "typu v katalogu zpresni az druha faze.\n")
    with open(os.path.join(out_dir, "CONVERZE.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))


def main():
    ap = argparse.ArgumentParser(description="Dekoduje a analyzuje FAND aplikaci.")
    ap.add_argument("folder", nargs="?", default=".", help="slozka s .rdb/.ttt")
    ap.add_argument("--out", default=None, help="vystupni slozka")
    ap.add_argument("--include-deleted", action="store_true",
                    help="vystup i logicke smazane zaznamy (flag!=0)")
    args = ap.parse_args()
    out = args.out or os.path.join(args.folder, "fand_unlock_out")
    process(args.folder, out, include_deleted=args.include_deleted)


if __name__ == "__main__":
    sys.exit(main())

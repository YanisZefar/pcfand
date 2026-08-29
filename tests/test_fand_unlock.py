import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fand_unlock as F


class TestLicNr(unittest.TestCase):
    def test_read_licnr(self):
        ttt = bytearray(512)
        struct.pack_into("<H", ttt, 458, 22780)
        self.assertEqual(F.read_licnr(bytes(ttt)), 22780)
        self.assertEqual(F.read_licnr(b""), 0)


class TestRdbCatalog(unittest.TestCase):
    def test_parse_kabely2_catalog(self):
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "aplikace_pcfand", "KABELY2.RDB")
        if not os.path.isfile(base):
            self.skipTest("KABELY2.RDB not present")
        info = F.parse_rdb(base)
        self.assertEqual(info["nrecs"], 79)
        self.assertEqual(info["reclen"], 24)
        self.assertTrue(info["catalog"])
        self.assertGreater(len(info["records"]), 70)
        names = {r["name"] for r in info["records"]}
        self.assertIn("Fnw_data", names)


class TestSchemaParsing(unittest.TestCase):
    def test_parse_schema_fields(self):
        text = ("Datum:D; Mechanik:A,20!; Cislo:F,9.0; Cat:N,2; "
                "Blokovan:B").encode(F.CP852)
        fields = F.parse_schema_fields(text)
        by = {f["name"]: f for f in fields}
        self.assertEqual(by["Datum"]["type"], "D")
        self.assertEqual(by["Mechanik"]["type"], "A")
        self.assertEqual(by["Mechanik"]["L"], 20)
        self.assertEqual(by["Cislo"]["type"], "F")
        self.assertEqual(by["Cislo"]["M"], 0)
        self.assertEqual(by["Cat"]["type"], "N")
        self.assertEqual(by["Blokovan"]["type"], "B")
        # offsets must be contiguous starting at 0, sum + 1 == RecLen
        self.assertEqual(fields[0]["off"], 0)
        off = 0
        for f in fields:
            self.assertEqual(f["off"], off)
            off += f["nbytes"]
        self.assertEqual(off, sum(f["nbytes"] for f in fields))


class TestFieldDecoders(unittest.TestCase):
    def test_decode_A_xorAA(self):
        # A fields are stored XOR-AA encrypted (CP852 text)
        plain = "Tučková Zdeňka".encode(F.CP852)
        enc = F.xorAA(plain)
        self.assertEqual(F._decode_A(enc), "Tučková Zdeňka")
        self.assertEqual(F._decode_A(F.xorAA(b"")), "")
        self.assertEqual(F._decode_A(bytes([0x8A] * 5)), "")

    def test_decode_F_bigendian(self):
        f = {"type": "F", "M": 0, "L": 0, "nbytes": 4, "off": 0, "name": "x"}
        self.assertEqual(F._decode_field(bytes([0, 0, 0, 0x24]), f), 36)
        self.assertEqual(F._decode_field(bytes([0xFF, 0xFF, 0xFF, 0xFF]), f), "")
        f2 = {"type": "F", "M": 2, "L": 0, "nbytes": 4, "off": 0, "name": "x"}
        self.assertAlmostEqual(F._decode_field(bytes([0, 0, 0, 0x24]), f2), 0.36)

    def test_decode_N_bcd(self):
        f = {"type": "N", "M": 0, "L": 0, "nbytes": 2, "off": 0, "name": "x"}
        self.assertEqual(F._decode_field(bytes([0x12, 0x34]), f), 1234)
        self.assertEqual(F._decode_field(bytes([0, 0]), f), "")

    def test_bcd_to_int(self):
        self.assertEqual(F._bcd_to_int(bytes([0x12, 0x34])), 1234)
        self.assertEqual(F._bcd_to_int(bytes([0x12, 0x3D])), -123)

    def test_tp_real(self):
        # REAL48 of 1.0 is 0x81 00 00 00 00 00
        self.assertAlmostEqual(F._tp_real(bytes([0x81, 0, 0, 0, 0, 0])), 1.0)

    def test_fand_serial_to_date(self):
        NODAY = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

        def olympyear(y):
            return (y % 4 == 0) and ((y % 100 != 0) or (y % 400 == 0))

        def olympyears(y):
            if y < 3:
                return 0
            y -= 1
            return y // 4 - y // 100 + y // 400

        def rdate(Y, M, D):
            l = (Y - 1) * 365 + olympyears(Y) + D
            for i in range(1, M):
                l += NODAY[i - 1]
            if M > 2 and olympyear(Y):
                l += 1
            return l

        self.assertEqual(F.fand_serial_to_date(rdate(1995, 6, 15)), (1995, 6, 15))
        self.assertEqual(F.fand_serial_to_date(rdate(2000, 12, 31)), (2000, 12, 31))

    def test_decode_D(self):
        # build a REAL48 for serial 728459 (1995-06-15) and decode it
        serial = 728459
        # REAL48: exp byte = floor(log2(serial)) + 129, mantissa normalized
        import math
        e = serial.bit_length() - 1 + 129
        # mantissa = (serial / 2^(e-129) - 1) * 2^39, packed big-endian in bytes 1..5
        frac = serial / (2 ** (e - 129)) - 1.0
        mant = int(round(frac * (2 ** 39))) & 0x7FFFFFFFFF
        b = bytes([e]) + mant.to_bytes(5, "big")
        f = {"type": "D", "M": 0, "L": 0, "nbytes": 6, "off": 0, "name": "x"}
        self.assertEqual(F._decode_field(b, f), "1995-06-15")

    def test_decode_D_mode8(self):
        # '8' režim: 2B signed int = RDate_serial - FIRSTDATE (697248)
        f = {"type": "D", "M": 0, "L": 0, "nbytes": 6, "off": 0, "name": "x"}
        serial = 728459  # 1995-06-15
        v = serial - F.FIRSTDATE
        b = struct.pack("<h", v) + b"\x00\x00\x00\x00"
        self.assertEqual(F._decode_field(b, f, file_type=0x38), "1995-06-15")
        # empty marker v==0 -> ""
        self.assertEqual(F._decode_field(b"\x00\x00\x00\x00\x00\x00", f,
                                          file_type=0x38), "")

    def test_decode_D_modeD(self):
        # 'D' režim: 8-znakový řetězec 'YYYYMMDD'
        f = {"type": "D", "M": 0, "L": 0, "nbytes": 8, "off": 0, "name": "x"}
        b = b"19950615\x00\x00"
        self.assertEqual(F._decode_field(b, f, file_type=0x44), "1995-06-15")
        self.assertEqual(F._decode_field(b"\x00\x00\x00\x00\x00\x00\x00\x00",
                                          f, file_type=0x44), "")

    def test_decode_D_modeD_with_time(self):
        # 'D' režim dokáže nést i 14 znaků 'YYYYMMDDHHMMSS' (datum a čas)
        f = {"type": "D", "M": 0, "L": 0, "nbytes": 14, "off": 0, "name": "x"}
        b = b"19950615123000"
        self.assertEqual(F._decode_field(b, f, file_type=0x44),
                         "1995-06-15 12:30:00")

    def test_serial_to_datetime(self):
        # čisté datum (zlomek 0) -> bez času
        self.assertEqual(F._serial_to_datetime(1.0), "0001-01-01")
        # poledne (zlomek 0.5) -> čas se zachová
        self.assertEqual(F._serial_to_datetime(1.5), "0001-01-01 12:00:00")

    def test_decode_D_real48_with_time(self):
        # Výchozí REAL48 větev: zlomek dne nese čas (FAND "datum a čas").
        import math

        def real48(val):
            exp = int(math.floor(math.log2(val))) if val >= 1 else 0
            e = exp + 129
            frac = val / (2 ** exp) - 1.0
            mant = int(round(frac * (2 ** 39))) & 0x7FFFFFFFFF
            return bytes([e]) + mant.to_bytes(5, "big")

        f = {"type": "D", "M": 0, "L": 0, "nbytes": 6, "off": 0, "name": "x"}
        # čisté datum (zlomek 0) -> bez času
        self.assertEqual(F._decode_field(real48(728459.0), f), "1995-06-15")
        # datum + poledne (zlomek 0.5) -> čas se zachová
        self.assertEqual(F._decode_field(real48(728459.5), f),
                         "1995-06-15 12:00:00")


class TestSchemaKey(unittest.TestCase):
    def test_schema_key(self):
        self.assertEqual(F._schema_key("FData.x"), "data")
        self.assertEqual(F._schema_key("data.000".replace(".000", "")), "data")
        self.assertEqual(F._schema_key("EEDATA"), "eedata")


if __name__ == "__main__":
    unittest.main()

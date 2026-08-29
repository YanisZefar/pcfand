# AGENTS.md — PC FAND 4.2x

Projekt je dekodér/reverse-engineering PC FAND aplikací. Hlavní instrukce a
konvence jsou v `CLAUDE.md` (čeština, uživatel preferuje češtinu). Tento soubor
je doplněk s tím, co by agent snadno přehlédl.

## Co je v této repo spustitelné
- **Jen Python je spustitelný.** Pascal (`pas/`) se překládá Borland Pascalem 7 pod
  DOSBoxem a v tomto prostředí se **nedá sestavit ani spustit** — nepokoušej se o
  kompilaci/linkování, jen čti zdrojáky jako dokumentaci (např. `pas/ACCESS.PAS`
  popisuje kódování polí).
- Kanonický dekodér: `xdecode.py`. Starší/experimentální: `xdecode_fixed.py`,
  `read_ttt_full.py` (importují z `xdecode_fixed`), `rdbparse.py` (pomocné
  `parse_catalog`). Neupravuj tyto starší skripty, pokud není účel jasný.

## Příkazy
- Dekódování TFile/segmentu:
  `python3 xdecode.py <input> <output> [--format x|xor-aa|both] [--mode segment|full|tfile|wtfile|rtfile|tcat] [--rdb CATALOG.RDB] [--outdir DIR] [--rdb-out PATH]`
  - Výchozí `--format` je `both` (ne `x`, jak píše starší `CLAUDE.md` — kód je
    zdroj pravdy).
  - `--mode tcat` i `--mode wtfile` vyžadují `--rdb <párový .rdb katalog>`.
  - `--mode tfile` reassembluje LongStr přes 512B stránky a dekóduje XEncode/XOR-AA.
- CSV/export aplikace: `python3 fand_unlock.py [--out DIR] [--include-deleted] <složka>`
  (výchozí `--out` = `<složka>/fand_unlock_out`). Generuje CSV tabulky, dekódované
  texty a `CONVERZE.md`.

## Testy
- `python3 -m pytest tests/ -q`. **pytest není předinstalován** → nejprv
  `pip install pytest`. Testy používají vzorová data v `aplikace_pcfand/` (ta musí
  být na disku; `KABELY2.RDB` je gitignored, ale přítomen).
- Třídy: `test_rdb.py`, `test_samples.py` (TFile/katalog, vyžadují vzorky),
  `test_fand_unlock.py` (dekodéry polí).

## Dekódovací zvláštnosti (ověřeno, snadno se s nimi překlikne)
- **REAL48 mantisa je na disku LITTLE-ENDIAN.** FAND ukládá 5 bajtů mantisy
  REAL48 (datum/čísla) little-endian, ne big-endian. `fand_unlock._tp_real` to už
  řeší — nepřepisuj to zpět na big-endian, jinak budou data (rok ~1434) prázdná.
- **Textová pole (`A`) a memo (`T`):** kódování podle `ACCESS.PAS`:
  `Code` = XOR `0xAA` (když `LicenseNr` šablony == 0), `XDecode` (LZ77 + rotující
  `RMask`, `ACCESS.PAS:903`) když `LicenseNr != 0`; některé tabulky ukládají memo
  jako čistý plaintext. `fand_unlock._decode_memo_blob` zkouší postupně
  plaintext → XOR `0xAA` → `XDecode` a vrací nejčitelnější. `Heslo` i ostatní `A`
  pole jdou přes `fand_unlock._decode_A`, které zkouší **plaintext i XOR `0xAA`**
  a vrací první čitelnou variantu (např. `FZavery.x.Zaver` je plaintext, `FData.x`
  je XOR `0xAA`) — obě větve jsou správně, neměň bez ověření na vzorcích.
- **Typ `D` (datum) nese i čas:** celočíselná část REAL48 = datumový serial (dny od
  1. 1. 0001), **zlomek dne = čas**. Viz `fand_serial_to_date` + `_serial_to_datetime`.
  Režim `'8'`: 2B signed int = serial − `FIRSTDATE` (697248 = 1. 1. 1910).
- **`.ttt` hlavička:** `LicNr` je na bajtovém offsetu 458 (`LICNR_OFF`).
- **`.rdb` katalog:** záznam 24 B, `txtpos` (u32) na offsetu 20; offset textu v
  `.ttt` = `txtpos − LicNr`. (KABELY2 má `LicNr = 22780`.)

## .gitignore a disciplína commitů
- Generované výstupy jsou gitignored — **necommituj je**: `aplikace_pcfand/decoded_full/*.txt`,
  `aplikace_pcfand/fand_unlock_out/*.csv`, `aplikace_pcfand/fand_unlock_out/decoded/`.
- Gitignored vzorky: `KABELY2.RDB/TTT`, `POKUS.*`.
- Datové/binární soubory aplikace, které uživatel ručně přidal do `aplikace_pcfand/`
  (`*.000`, `*.t00`, `*.x00`, `*.rdb`, `*.ttt`, `*.exe`, `*.com`, `*.bat`,
  `HESLO.*` atd.), jsou **untracked a mohou obsahovat hesla** (např. pole `Heslo`
  v `FUSERDATA.X`) i jiná citlivá data.
  **TYTO SOUBORY NEKOMITOVAT NIKDY!!!** (ani částečně, ani na výzvu „commitni
  všechno" — vždy je nejdřív odeber ze stagingu.)
- Obecně: necommituj generované výstupy ani data, pokud to není výslovně řečeno.

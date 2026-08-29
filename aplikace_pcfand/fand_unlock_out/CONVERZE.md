# Zprava o dekodovani FAND aplikace

**Slozka:** `aplikace_pcfand`  

**Dekodovano kapitol:** 13  

**Extrakovano poli schématu:** 4  

**Datovych tabulek (CSV):** 0  

**Samostatnych .ttt/.t00:** 0


## Poznamky

- Znakova sada zdroje je CP852 (Kamenicky); dekodovany text je ulozen v UTF-8. Binary .rdb/.ttt zachovavaji pusodni bajty.

- Katalog .rdb: 6B hlavicka (NRecs u32, RecLen u16) + 24B zaznamy (Typ @0, Nazev @7, TxtPos u32 @20). TxtPos - LicNr (v .ttt @458) = pozice textu.

- Re-kodovany NEZASIFROVANY .ttt zapisovac je odlozen (viz nize); vystupem je zaruka citelny plain-text export.


## Katalog

| aplikace | typ | nazev | txtpos | pozice | dekodovano | delka |
|---|---|---|---|---|---|---|
| POKUS | 0 | FSoubor | 1798 | 1798 | ano | 95 |
| POKUS | 0 | FSoubSif | 1434 | 1434 | ano | 15 |
| POKUS | 0 | PMain | 642 | 642 | ano | 211 |
| POKUSHA | 0 | FSoubor | 512 | 512 | ano | 18 |
| POKUSHA | 0 | PMain | 642 | 642 | ano | 127 |
| POKUSHAB | 0 | FSoubor | 512 | 512 | ano | 18 |
| POKUSHAB | 0 | PMain | 642 | 642 | ano | 127 |
| POKUSHB | 0 | FSoubor | 512 | 512 | ano | 18 |
| POKUSHB | 0 | PMain | 642 | 642 | ano | 127 |
| POKUSHC | 0 | FSoubor | 512 | 512 | ano | 18 |
| POKUSHC | 0 | PMain | 642 | 642 | ano | 127 |
| POKUSSI2 | 0 | FSoubor | 23292 | 512 | ano | 16 |
| POKUSSI2 | 0 | PMain | 23429 | 649 | ano | 168 |

## Schmata (ukazka poli)

| aplikace | objekt | poradi | pole | typ | delka |
|---|---|---|---|---|---|
| POKUS | FSoubor | 1 | kaA | A | 10 |
| POKUS | FSoubor | 2 | kaN | N | 5 |
| POKUS | FSoubor | 3 | kaF | F | 10 |
| POKUSSI2 | FSoubor | 1 | ka | A | 10 |

## Datove tabulky

_Zadne datove soubory (.X/.000/.dbf) nebyly nalezeny - konverze radku ceka na dodani dat._


## Omezeni / dalsi kroky

1. Zapis loadovatelneho nezasifrovaneho .ttt (TFile) vyžaduje implementaci zapisovace a overeni v DOSBoxu/FANDu.

2. Konverze skutecnych dat (CSV) bude spustena az po dodani datovych souboru.

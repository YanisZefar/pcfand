# KABELY2 – kompletně dekódovaný zdrojový kód úlohy

Rozlousknuto: `_KABELY2.RDB` + `_KABELY2.TTT` → **78/78 kapitol úspěšně dekódováno**.

## Jak to bylo zakódované

Formát PC FAND (`XEncode`): pozice textu v `.TTT` je uložena v katalogu s korekcí o
`LicenseNr` (z hlavičky souboru, u KABELY2 = 22780). Samotný text je uložen jako
komprimovaný/obfuskovaný blok:

- rotující XOR maska (start 0x9C, rotuje se PŘED použitím na každý literál),
- zpětné odkazy (LZ-styl) pro opakující se sekvence,
- 2bajtová délka na začátku, časový bajt + XOR-maskovaný displacement na konci.

Funkční dekodér: `xdecode_fixed.py` + `read_ttt_full.py` (řeší i vícestránkový text).

## Obsah

Viz `_manifest.tsv` pro úplný seznam. Klíčové soubory:

| Soubor | Co obsahuje |
|---|---|
| `017_P_MAIN.txt` | Celé hlavní menu aplikace (19 811 znaků) |
| `002_F_USERDATA.X.txt` | Přesná struktura tabulky uživatelů a práv |
| `013_F_Data.x.txt` | Přesná struktura hlavní tabulky karet kabelů |
| `069_P_PRIHLASENINW.txt` | Síťové přihlašování – vysvětluje "tiché ukončení" |
| `068_P_PRIHLASENI.txt` | Alternativní (ne-síťové) přihlašování |

## Klíčové zjištění: proč se aplikace tiše ukončí

`PRIHLASENINW` hledá v `UserData/dle_hesla` (index podle pole `Heslo`) záznam, kde
`Heslo = jméno_uživatele_ze_sítě` (u nás "jantar") AND `Akce = 'KABELY2'`.
Bez souboru `USERDATA.X` s takovým záznamem volá `cancel` → tichý návrat do menu.

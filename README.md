# jdbisam

Read-only access to DBISAM tables (`.dat` + `.blb`) from Kotlin/Java.

```kotlin
DbisamTable.open(Path.of("customers.dat")).use { table ->
    for (row in table.rows()) {
        println("${row.recordId}: ${row["Name"]}")
    }
}
```

Encrypted tables need the password: `DbisamTable.open(path, password)`, or `JDBISAM_PASSWORD` for the CLI.

```shell
mvn install                                           # library in the local Maven repo
mvn -q exec:java -Dexec.args="schema path/to/x.dat"   # columns
mvn -q exec:java -Dexec.args="csv path/to/x.dat"      # data as CSV
```

## Values

| Column type | Kotlin value |
|---|---|
| STRING | `String` (Windows-1252, up to the first NUL) |
| DATE / TIME / TIMESTAMP | `LocalDate` / `LocalTime` / `LocalDateTime` |
| BOOLEAN | `Boolean` |
| SMALLINT / INTEGER, AUTOINC / LARGEINT | `Short` / `Int` / `Long` |
| FLOAT, CURRENCY | `Double` |
| BLOB, MEMO, GRAPHIC | `DbisamTable.Blob`, read lazily with `bytes()` or `text()` |
| BCD | raw `ByteArray`, not decoded |

`null` means the column's null flag is clear. Delphi's zero date 1899-12-30 is returned as is.

Errors: `DbisamFormatException` when a table cannot be read at all (empty, inconsistent, missing or wrong password),
`DamagedBlobException` for a single damaged blob; the rest of the table stays readable.

## Change detection

DBISAM keeps no change log. Use `row.recordId` as key and `row.contentHash()` to see whether a row changed;
the header's `lastModified` matches the file's modification time, so unchanged tables can be skipped.
Blob contents are not part of the hash.

## File format

All little-endian. What is listed here was checked against a real database; anything else is unknown.

**Header** (512 bytes): row count `u32 @0x29`, row size `u16 @0x2D`, column count `u16 @0x2F`,
last modified `f64 @0x3F` (days since 3798-12-28), description length `u8 @0x47` + text `@0x48`,
user version `u16 @0xC1` + `u8 @0xC3`, encrypted flag `u8 @0xAC`, password check `16 bytes @0xAD`.

**Columns**: one 768-byte block per column from 0x200: number `u16 @0` (from 1), name length `u8 @2` + name `@3`,
type `u16 @0xA4`, declared length `u16 @0xA6` (strings), offset in row `u16 @0xAC`.

**Rows** follow the column blocks: deleted flag `@0`, record id `u32 @5`, checksum `16 bytes @9`, columns from 25.
Each column starts with a null-flag byte, then the value.

| Type code | Type | Bytes |
|---|---|---|
| 0x01 | string | declared length + 1 |
| 0x02 | date, days from 0001-01-01 (= 1) | 4 |
| 0x03 / 0x1603 / 0x1A03 | blob / memo / graphic | 8: first block `u32`, blob id `u32` |
| 0x04 | boolean | 2 |
| 0x05 / 0x06 / 0x12 | 16 / 32 / 64-bit integer | 2 / 4 / 8 |
| 0x07 / 0x1507 | float / currency, IEEE double | 8 |
| 0x08 | BCD (Delphi `TBcd`) | 34 |
| 0x0A | time, ms since midnight | 4 |
| 0x0B | timestamp, ms since 0001-01-01 minus one day, as double | 8 |
| 0x1D06 | autoinc | 4 |

**Encryption**: Blowfish-CBC with a zero IV, key = MD5 of the password (Windows-1252). The header itself is not
encrypted. The column blocks together form one CBC stream, and each row is its own stream; encrypted tables have
row sizes that are a multiple of 8. The password check is the key encrypted with itself.

**Blobs** (`.blb`): 512-byte blocks, block 0 is a header. Each block: previous `u32 @0`, next `u32 @4` (0 = last),
bytes used `u16 @8`, data from 18. The first block of a blob also has its id `u32 @10` and total size `u32 @14`.

## Known gaps

- Blobs of encrypted tables are refused (`UnsupportedOperationException`): no example seen yet. Passwords with
  non-ASCII characters are untested.
- BOOLEAN, LARGEINT, BCD and GRAPHIC were seen with very few or no values, so their decoding is weakly verified.
- Some blob chains hold more bytes than their declared size; these are reported as damaged.
- Whether `recordId` survives a restructure, and whether a memo edit changes the row, needs two snapshots to verify.

## Tests

`mvn verify` runs tests on generated tables. `JDBISAM_TESTDATA=<dir> mvn test` also reads every `.dat` under `<dir>`
and checks invariants without printing any data; set `JDBISAM_PASSWORD` to include encrypted tables. Keep real databases out of the repo; `testdata-private/` is ignored.

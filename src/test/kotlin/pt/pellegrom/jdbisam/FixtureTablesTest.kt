package pt.pellegrom.jdbisam

import java.math.BigDecimal
import java.nio.file.Path
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Tables made with DBISAM 4.52 itself from made-up data; the .txt files next to them say what went in. */
class FixtureTablesTest {
    private fun open(name: String, password: String? = null) = DbisamTable.open(Path.of("src/test/resources/dbisam/$name.dat"), password)

    private fun DbisamTable.values() = rows().map { row ->
        columns.associate { column ->
            column.name to when (val v = row[column]) {
                is DbisamTable.Blob -> if (column.type == ColumnType.MEMO) v.text() else v.bytes().size
                is ByteArray -> v.toList()
                else -> v
            }
        }
    }.toList()

    private fun bytes(text: String) = text.toByteArray().toList()

    @Test
    fun `all column types`() = open("alltypes").use { table ->
        assertEquals("Testtabel alle types", table.description)
        assertEquals("3.7", table.userVersion)
        val rows = table.values()
        assertEquals(5, rows.size)
        assertEquals(
            mapOf(
                "id" to 1, "f_string" to "Hallo", "f_fixedchar" to "Vast", "f_guid" to "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}",
                "f_bytes" to bytes("ABCDEFGH"), "f_varbytes" to bytes("Hallo"), "f_blob" to 92, "f_graphic" to 4150,
                "f_memo" to "Korte memo €é", "f_date" to LocalDate.of(2024, 2, 29), "f_time" to LocalTime.of(13, 45, 12, 345_000_000),
                "f_timestamp" to LocalDateTime.of(2024, 2, 29, 13, 45, 12, 345_000_000), "f_boolean" to true,
                "f_smallint" to 123.toShort(), "f_word" to 456, "f_integer" to 42, "f_autoinc" to 1, "f_largeint" to 5_000_000_000L,
                "f_float" to 3.14159, "f_currency" to 12.34, "f_bcd" to BigDecimal("123.45"),
            ),
            rows[0],
        )
        assertEquals(mapOf("id" to 2, "f_autoinc" to 2), rows[1].filterValues { it != null })
        assertEquals(
            mapOf(
                "id" to 3, "f_string" to "€éëß'ABCDE", "f_bytes" to bytes("AB") + List(6) { 0.toByte() },
                "f_varbytes" to bytes("0123456789ABCDEF"), "f_memo" to "Lorem ipsum €é ".repeat(110),
                "f_date" to LocalDate.of(1, 1, 1), "f_time" to LocalTime.of(23, 59, 59, 999_000_000),
                "f_timestamp" to LocalDateTime.of(1899, 12, 30, 0, 0), "f_boolean" to false, "f_smallint" to (-32768).toShort(),
                "f_word" to 65535, "f_integer" to -1, "f_autoinc" to 3, "f_largeint" to -5_000_000_000L,
            ),
            rows[2].filterValues { it != null },
        )
        // DBISAM stores '' as NULL.
        assertEquals(
            mapOf("id" to 4, "f_date" to LocalDate.of(9999, 12, 31), "f_autoinc" to 4, "f_float" to 0.0, "f_currency" to -0.01, "f_bcd" to BigDecimal("-1.00")),
            rows[3].filterValues { it != null },
        )
        // Trailing spaces are trimmed on insert; leftovers after the NUL are ignored.
        assertEquals(mapOf("id" to 5, "f_string" to "spaties", "f_date" to LocalDate.of(1850, 6, 15), "f_autoinc" to 5), rows[4].filterValues { it != null })
    }

    @Test
    fun `bcd with every scale DBISAM allows`() = open("bcd").use { table ->
        // DBISAM accepts scale 0..4; it rounds extra decimals (row 7) and stored 99999999999999.9999 as 1E14 (row 6).
        val expected = mapOf(
            1 to listOf("0", "0.0", "0.00", "0.0000"),
            2 to listOf("1", "1.0", "1.00", "1.0000"),
            3 to listOf("-1", "-1.0", "-1.00", "-1.0000"),
            4 to listOf("12345", "1234.5", "123.45", "1234567.8901"),
            5 to listOf("-7", "-0.5", "-0.01", "-0.0001"),
            6 to listOf("9999999999", "999999999.9", "99999999.99", "100000000000000.0000"),
            7 to listOf("2", "1.3", "1.26", "1.1235"),
            8 to listOf(null, null, null, null),
        ).mapValues { (_, v) -> v.map { it?.let(::BigDecimal) } }
        assertEquals(expected, table.rows().associate { r -> r["id"] as Int to listOf("b0", "b1", "b2", "b4").map { r[it] } })
    }

    @Test
    fun `varbytes keep no length`() = open("varbytes").use { table ->
        // Rows 1 and 2 ('A' and 'A' + #0) are identical on disk; rows 3-5 hold leftover bytes DBISAM wrote after a #0.
        fun hex(vararg b: Int) = b.map { it.toByte() }
        val expected = mapOf(
            1 to hex(0x41), 2 to hex(0x41), 3 to hex(0x41, 0, 0x52, 0, 0xD0), 4 to hex(0, 0xB8), 5 to hex(0x41, 0, 0x53),
            6 to hex(0x41, 0x42), 7 to bytes("ABCDEFG"), 8 to null,
        )
        assertEquals(expected, table.values().associate { it["id"] as Int to it["v"] })
    }

    @Test
    fun `encrypted tables, blobs and a non-ASCII password`() {
        val plain = open("alltypes").use { t -> t.values().take(2) to t.rows().take(2).map { it.contentHash().toList() }.toList() }
        open("enc_all", "Test1234").use { t ->
            assertEquals(plain.first, t.values())
            assertEquals(plain.second, t.rows().map { it.contentHash().toList() }.toList())
            val first = t.rows().first()
            assertEquals("jdbisam test blob: made-up bytes, no real data. ".repeat(2).take(92), (first["f_blob"] as DbisamTable.Blob).text())
            assertContentEquals("BM".toByteArray(), (first["f_graphic"] as DbisamTable.Blob).bytes().copyOf(2))
        }
        open("enc_odd", "Tést€1").use { t -> assertEquals(listOf("a", "bb", "ccc"), t.rows().map { it["s"] }.toList()) }
        assertFailsWith<DbisamFormatException> { open("enc_odd", "Test1234") }
    }

    @Test
    fun `record ids and content hashes across edits, optimize and repair`() {
        val steps = (0..7).map { step ->
            open("changes/stap$step/changes").use { t -> t.rows().associate { it.recordId to Pair(it["notitie"].let { b -> (b as DbisamTable.Blob).text() }, it.contentHash().toList()) } }
        }
        assertEquals(setOf(1, 2, 3, 4, 5), steps[0].keys)
        fun changed(from: Int, to: Int) = steps[to].keys.filter { steps[from][it]?.second != steps[to][it]!!.second }.toSet()
        assertEquals(setOf(2), changed(0, 1)) // amount
        assertEquals(setOf(3), changed(1, 2)) // memo grown
        assertEquals("Lorem ipsum €é ".repeat(110), steps[2][3]!!.first)
        assertEquals(setOf(3), changed(2, 3)) // memo shrunk; its old block chain stays behind
        assertEquals("Kort", steps[3][3]!!.first)
        assertEquals(setOf(1, 2, 3, 5), steps[4].keys) // deleted
        assertEquals(setOf(1, 2, 3, 5, 6), steps[5].keys) // the new row reuses the slot, not the id
        assertEquals(steps[5], steps[6]) // optimize moves blobs, values stay
        assertEquals(steps[5], steps[7]) // repair
        assertEquals(setOf(3), changed(0, 6).intersect(setOf(3))) // also across an optimize
        open("changes/stap4/changes").use { t -> assertTrue(t.rows(includeDeleted = true).single { it.deleted }.recordId == 4) }
        open("changes/stap4/changes").use { t -> assertNull(t.rows(includeDeleted = true).single { it.deleted }["notitie"]) }
    }
}

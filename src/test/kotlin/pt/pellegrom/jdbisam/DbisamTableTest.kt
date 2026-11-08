package pt.pellegrom.jdbisam

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

private fun le(size: Int) = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)

/** Writes small invented tables to a temp directory; no fixture comes from a real database. */
private class Fixture(vararg val cols: Pair<String, Int>) {
    /** Rounded up to whole cipher blocks, as encrypted tables need. */
    val rowSize = (25 + cols.sumOf { 1 + widthOf(it.second) } + 7) / 8 * 8
    private val rows = mutableListOf<ByteBuffer>()
    val dir: Path = createTempDirectory("jdbisam")

    private fun widthOf(code: Int) = ColumnType.entries.first { it.code == code }.width ?: 11
    fun offsetOf(i: Int) = 25 + cols.take(i).sumOf { 1 + widthOf(it.second) }

    /** A blank row; [fill] gets each column's value position after flagging it non-null. */
    fun row(deleted: Boolean = false, fill: ByteBuffer.(set: (Int) -> Int) -> Unit = {}) {
        val b = le(rowSize)
        if (deleted) b.put(0, 1)
        b.putInt(5, 100 + rows.size)
        b.fill { i -> b.put(offsetOf(i), 1); offsetOf(i) + 1 }
        rows += b
    }

    private fun blowfish(mode: Int, key: SecretKeySpec) =
        Cipher.getInstance("Blowfish/CBC/NoPadding").apply { init(mode, key, IvParameterSpec(ByteArray(8))) }

    fun dat(password: String? = null, tweak: ByteBuffer.() -> Unit = {}): ByteArray {
        val b = le(512 + cols.size * 768 + rows.size * rowSize)
        b.putInt(0x29, rows.count { it.get(0).toInt() == 0 }).putShort(0x2D, rowSize.toShort()).putShort(0x2F, cols.size.toShort())
        b.putDouble(0x3F, -2.0)
        b.put(0x47, 2).put(0x48, "hi".toByteArray())
        b.putShort(0xC1, 14).put(0xC3, 2)
        cols.forEachIndexed { i, (name, code) ->
            val at = 512 + i * 768
            b.putShort(at, (i + 1).toShort()).put(at + 2, name.length.toByte()).put(at + 3, name.toByteArray())
            b.putShort(at + 0xA4, code.toShort()).putShort(at + 0xA6, 10).putShort(at + 0xAC, offsetOf(i).toShort())
        }
        rows.forEachIndexed { i, row -> b.put(512 + cols.size * 768 + i * rowSize, row.array()) }
        b.tweak()
        if (password != null) {
            val key = SecretKeySpec(MessageDigest.getInstance("MD5").digest(password.toByteArray(charset("windows-1252"))), "Blowfish")
            fun encrypt(from: Int, length: Int) {
                b.put(from, blowfish(Cipher.ENCRYPT_MODE, key).doFinal(b.array(), from, length))
            }
            b.put(0xAC, 1).put(0xAD, blowfish(Cipher.ENCRYPT_MODE, key).doFinal(key.encoded))
            encrypt(512, cols.size * 768)
            rows.indices.forEach { encrypt(512 + cols.size * 768 + it * rowSize, rowSize) }
        }
        return b.array()
    }

    fun open(dat: ByteArray = dat(), blb: ByteArray? = null, password: String? = null): DbisamTable {
        dir.resolve("t.dat").writeBytes(dat)
        Files.deleteIfExists(dir.resolve("t.blb"))
        blb?.let { dir.resolve("t.blb").writeBytes(it) }
        return DbisamTable.open(dir.resolve("t.dat"), password)
    }
}

class DbisamTableTest {
    @Test
    fun `decodes each column type, null flags and deleted rows`() {
        val f = Fixture(
            "s" to 0x0001, "d" to 0x0002, "b" to 0x0004, "si" to 0x0005, "i" to 0x0006, "fl" to 0x0007,
            "t" to 0x000A, "ts" to 0x000B, "li" to 0x0012, "cur" to 0x1507, "ai" to 0x1D06,
        )
        val day = 738_886 // 2024-01-01
        f.row {
            put(it(0), "café\u0000old".toByteArray(Charsets.ISO_8859_1))
            putInt(it(1), day)
            putShort(it(2), 1)
            putShort(it(3), -2)
            putInt(it(4), -3)
            putDouble(it(5), 1.5)
            putInt(it(6), 3_600_500)
            putDouble(it(7), day * 86_400_000.0 + 3_600_500.0)
            putLong(it(8), 1L shl 40)
            putDouble(it(9), 9.95)
            putInt(it(10), 42)
        }
        f.row(deleted = true) { put(it(0), "gone".toByteArray()) }
        f.row()

        f.open().use { t ->
            assertEquals(2, t.declaredRowCount)
            assertEquals(LocalDateTime.of(3798, 12, 26, 0, 0), t.lastModified)
            assertEquals("hi", t.description)
            assertEquals("14.2", t.userVersion)

            val rows = t.rows().toList()
            assertEquals(
                listOf(
                    "café", LocalDate.of(2024, 1, 1), true, (-2).toShort(), -3, 1.5, LocalTime.of(1, 0, 0, 500_000_000),
                    LocalDateTime.of(2024, 1, 1, 1, 0, 0, 500_000_000), 1L shl 40, 9.95, 42,
                ),
                rows[0].values(),
            )
            assertEquals(42, rows[0]["ai"])
            assertEquals(List(11) { null }, rows[1].values())

            val all = t.rows(includeDeleted = true).toList()
            assertEquals(listOf(false, true, false), all.map { it.deleted })
            assertEquals(listOf(100, 101, 102), all.map { it.recordId })
            assertEquals(16, rows[0].contentHash().size)
            assertFalse(rows[0].contentHash().contentEquals(rows[1].contentHash()))
            assertEquals("gone", all[1]["s"])
        }
    }

    @Test
    fun `reads chained blobs and reports damage per blob`() {
        val content = ByteArray(600) { it.toByte() }
        val blb = le(5 * 512)
        fun block(n: Int, prev: Int, next: Int, used: Int, id: Int = 0, size: Int = 0) {
            val at = n * 512
            blb.putInt(at, prev).putInt(at + 4, next).putShort(at + 8, used.toShort()).putInt(at + 10, id).putInt(at + 14, size)
        }
        block(1, 0, 2, 494, id = 7, size = 600)
        blb.put(512 + 18, content, 0, 494)
        block(2, 1, 0, 106)
        blb.put(2 * 512 + 18, content, 494, 106)
        block(3, 0, 4, 494, id = 8, size = 10) // shrunk: the old chain stays, the size says where it ends
        block(4, 3, 0, 1, id = 11, size = 2) // continues another chain

        val f = Fixture("m" to 0x1603)
        for ((block, id) in listOf(1 to 7, 3 to 8, 99 to 9, 1 to 10, 4 to 11)) f.row { val at = it(0); putInt(at, block); putInt(at + 4, id) }

        f.open(blb = blb.array()).use { t ->
            val blobs = t.rows().map { it["m"] as DbisamTable.Blob }.toList()
            assertContentEquals(content, blobs[0].bytes())
            assertEquals(String(content, charset("windows-1252")), blobs[0].text())
            assertEquals(10, blobs[1].bytes().size)
            blobs.drop(2).forEach { assertFailsWith<DamagedBlobException> { it.bytes() } }
        }
        f.open().use { t ->
            assertFailsWith<DamagedBlobException> { (t.rows().first()["m"] as DbisamTable.Blob).bytes() }
        }
    }

    @Test
    fun `reads encrypted tables with the right password only`() {
        val f = Fixture("i" to 0x0006, "s" to 0x0001)
        f.row { putInt(it(0), 7); put(it(1), "x".toByteArray()) }
        val encrypted = f.dat(password = "s3cr\u00E9t")

        assertEquals(listOf<Any?>(7, "x"), f.open(encrypted, password = "s3cr\u00E9t").use { it.rows().single().values() })
        assertFailsWith<DbisamFormatException> { f.open(encrypted) }
        assertFailsWith<DbisamFormatException> { f.open(encrypted, password = "wrong") }
    }

    @Test
    fun `refuses what it cannot read`() {
        val f = Fixture("i" to 0x0006)
        f.row { putInt(it(0), 1) }
        val good = f.dat()
        assertEquals(1, f.open(good).use { it.rows().count() })

        assertFailsWith<DbisamFormatException> { f.open(ByteArray(0)) }
        assertFailsWith<DbisamFormatException> { f.open(good.copyOf(good.size - 1)) }
        assertFailsWith<DbisamFormatException> { f.open(f.dat { put(0xAC, 1) }) } // encrypted, no password
        assertFailsWith<DbisamFormatException> { f.open(f.dat { putShort(512, 9) }) }
        assertFailsWith<DbisamFormatException> { f.open(f.dat { putShort(512 + 0xA4, 0x7777) }) }
        assertFailsWith<DbisamFormatException> { f.open(f.dat { putShort(512 + 0xAC, 30_000) }) }
        assertFailsWith<DbisamFormatException> { f.open(f.dat { putShort(512 + 0xAC, 3) }) } // inside the row header
    }
}

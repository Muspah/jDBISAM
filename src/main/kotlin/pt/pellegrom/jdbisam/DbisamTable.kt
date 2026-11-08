package pt.pellegrom.jdbisam

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneOffset
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class DbisamFormatException(message: String) : IOException(message)
class DamagedBlobException(message: String) : IOException(message)

private val ANSI = Charset.forName("windows-1252")
private const val HEADER_SIZE = 512
private const val COLUMN_SIZE = 768
/** Deleted flag @0, record id @5, a checksum @9; columns start after it. */
private const val ROW_HEADER = 25
private const val BLOCK_SIZE = 512
private const val BLOCK_DATA = 18
private const val MILLIS_PER_DAY = 86_400_000L
/** Stored dates count days from 0001-01-01, which is day 1. */
private const val EPOCH_DAY_ORDINAL = 719_163L
/** Empirical: with this origin the header timestamp matches the file's modification time. */
private val MODIFIED_ORIGIN = LocalDateTime.of(3798, 12, 28, 0, 0)

private fun FileChannel.readAt(position: Long, size: Int): ByteBuffer {
    val buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
    while (buffer.hasRemaining()) {
        if (read(buffer, position + buffer.position()) < 0) throw EOFException("Unexpected end of file at ${position + buffer.position()}")
    }
    return buffer.clear()
}

/**
 * Encrypted tables use Blowfish-CBC with a zero IV, keyed with the MD5 of the password. The column area is one
 * CBC stream, each row another. The header holds the key encrypted with itself, which identifies the password.
 */
private class Decryptor(password: String) {
    private val key = SecretKeySpec(MessageDigest.getInstance("MD5").digest(password.toByteArray(ANSI)), "Blowfish")
    private val zeroIv = IvParameterSpec(ByteArray(8))

    fun matches(check: ByteArray) =
        Cipher.getInstance("Blowfish/CBC/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key, zeroIv) }.doFinal(key.encoded).contentEquals(check)

    fun decrypt(buffer: ByteBuffer): ByteBuffer {
        val cipher = Cipher.getInstance("Blowfish/CBC/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, zeroIv) }
        return ByteBuffer.wrap(cipher.doFinal(buffer.array())).order(ByteOrder.LITTLE_ENDIAN)
    }
}

private fun ByteBuffer.u8(at: Int) = get(at).toInt() and 0xFF
private fun ByteBuffer.u16(at: Int) = getShort(at).toInt() and 0xFFFF
private fun ByteBuffer.ansi(at: Int, length: Int) = String(array(), at, length, ANSI)

/** Read-only DBISAM table, read from disk on demand. Rows and their blobs stay usable until the table is closed. */
class DbisamTable private constructor(
    private val rows: FileChannel,
    private val blobs: FileChannel?,
    password: String?,
) : Closeable {
    val declaredRowCount: Long
    val rowSize: Int
    val lastModified: LocalDateTime
    val description: String?
    val userVersion: String
    val columns: List<Column>

    private val firstRow: Long
    private val slots: Long
    private val byName: Map<String, Column>
    private val decryptor: Decryptor?

    init {
        val fileSize = rows.size()
        if (fileSize < HEADER_SIZE) throw DbisamFormatException("Not a table: only $fileSize bytes")
        val header = rows.readAt(0, HEADER_SIZE)
        decryptor = if (header.u8(0xAC) == 0) null else {
            if (password == null) throw DbisamFormatException("Table is encrypted; a password is needed")
            val check = ByteArray(16).also { header.get(0xAD, it) }
            Decryptor(password).takeIf { it.matches(check) } ?: throw DbisamFormatException("Wrong password")
        }

        declaredRowCount = header.getInt(0x29).toLong() and 0xFFFFFFFFL
        rowSize = header.u16(0x2D)
        if (rowSize == 0) throw DbisamFormatException("Row size is 0")
        lastModified = MODIFIED_ORIGIN.plusSeconds(Math.round(header.getDouble(0x3F) * 86_400))
        description = header.u8(0x47).takeIf { it > 0 }?.let { header.ansi(0x48, it).trimEnd('\u0000') }
        userVersion = "${header.u16(0xC1)}.${header.u8(0xC3)}"

        val columnCount = header.u16(0x2F)
        firstRow = HEADER_SIZE + columnCount.toLong() * COLUMN_SIZE
        val rowBytes = fileSize - firstRow
        if (rowBytes < 0 || rowBytes % rowSize != 0L) throw DbisamFormatException("Row area of $rowBytes bytes does not fit rows of $rowSize bytes")
        slots = rowBytes / rowSize
        if (decryptor != null && rowSize % 8 != 0) throw DbisamFormatException("Encrypted rows of $rowSize bytes are not supported")

        val definitions = rows.readAt(HEADER_SIZE.toLong(), columnCount * COLUMN_SIZE).let { decryptor?.decrypt(it) ?: it }
        columns = List(columnCount) { readColumn(definitions, it) }
        byName = columns.associateBy { it.name }
    }

    private fun readColumn(definitions: ByteBuffer, position: Int): Column {
        val start = position * COLUMN_SIZE
        val def = ByteBuffer.wrap(definitions.array().copyOfRange(start, start + COLUMN_SIZE)).order(ByteOrder.LITTLE_ENDIAN)
        if (def.u16(0) != position + 1) throw DbisamFormatException("Column ${position + 1} is numbered ${def.u16(0)}")
        val name = def.ansi(3, def.u8(2))
        val code = def.u16(0xA4)
        val type = ColumnType.entries.find { it.code == code }
            ?: throw DbisamFormatException("Column $name has unknown type 0x${code.toString(16)}")
        val length = type.width ?: (def.u16(0xA6) + 1) // strings end in a NUL
        val offset = def.u16(0xAC)
        if (offset < ROW_HEADER || offset + 1 + length > rowSize) throw DbisamFormatException("Column $name does not fit in a row")
        return Column(position, name, type, offset, length)
    }

    /** Rows in file order. Deleted rows keep their old contents and are only returned on request. */
    fun rows(includeDeleted: Boolean = false): Sequence<Row> = sequence {
        for (slot in 0 until slots) {
            val bytes = rows.readAt(firstRow + slot * rowSize, rowSize)
            val row = Row(decryptor?.decrypt(bytes) ?: bytes)
            if (includeDeleted || !row.deleted) yield(row)
        }
    }

    override fun close() {
        rows.close()
        blobs?.close()
    }

    inner class Row internal constructor(private val bytes: ByteBuffer) {
        val deleted: Boolean get() = bytes.get(0).toInt() != 0

        /** Unique within a table; whether it survives a table restructure is not verified yet. */
        val recordId: Int get() = bytes.getInt(5)

        /**
         * MD5 of the column data, for change detection. Blob contents are not included, only their references.
         * Computed here because the checksum DBISAM stores in the row does not always match the data.
         */
        fun contentHash(): ByteArray =
            MessageDigest.getInstance("MD5").apply { update(bytes.array(), ROW_HEADER, rowSize - ROW_HEADER) }.digest()

        operator fun get(name: String): Any? =
            get(byName[name] ?: throw NoSuchElementException("No column named $name"))

        /** String, LocalDate, LocalTime, LocalDateTime, Boolean, Short, Int, Long, Double, Blob, ByteArray (undecoded BCD) or null. */
        operator fun get(column: Column): Any? {
            if (bytes.get(column.offset).toInt() == 0) return null
            val at = column.offset + 1
            return when (column.type) {
                ColumnType.STRING -> bytes.ansi(at, column.length).substringBefore('\u0000')
                ColumnType.DATE -> LocalDate.ofEpochDay(bytes.getInt(at) - EPOCH_DAY_ORDINAL)
                ColumnType.TIME -> LocalTime.ofNanoOfDay(bytes.getInt(at) * 1_000_000L)
                ColumnType.TIMESTAMP -> {
                    val millis = Math.round(bytes.getDouble(at)) - EPOCH_DAY_ORDINAL * MILLIS_PER_DAY
                    LocalDateTime.ofEpochSecond(Math.floorDiv(millis, 1000L), Math.floorMod(millis, 1000L).toInt() * 1_000_000, ZoneOffset.UTC)
                }
                ColumnType.BOOLEAN -> bytes.getShort(at).toInt() != 0
                ColumnType.SMALLINT -> bytes.getShort(at)
                ColumnType.INTEGER, ColumnType.AUTOINC -> bytes.getInt(at)
                ColumnType.LARGEINT -> bytes.getLong(at)
                ColumnType.FLOAT, ColumnType.CURRENCY -> bytes.getDouble(at)
                ColumnType.BLOB, ColumnType.MEMO, ColumnType.GRAPHIC -> Blob(bytes.getInt(at), bytes.getInt(at + 4))
                ColumnType.BCD -> bytes.array().copyOfRange(at, at + column.length)
            }
        }

        fun values(): List<Any?> = columns.map { this[it] }
    }

    /** Lazy reference into the .blb file; reading fails only for the blob that is actually damaged. */
    inner class Blob internal constructor(private val firstBlock: Int, private val id: Int) {
        @Throws(DamagedBlobException::class)
        fun text(): String = String(bytes(), ANSI)

        /**
         * Blocks form a doubly linked chain: previous @0, next @4, bytes used @8, data @18.
         * The first block also holds the blob id @10 and the total size @14.
         */
        @Throws(DamagedBlobException::class)
        fun bytes(): ByteArray {
            val file = blobs ?: throw DamagedBlobException("No .blb file")
            // ponytail: no encrypted table with blobs to learn the layout from yet.
            if (decryptor != null) throw UnsupportedOperationException("Blobs of encrypted tables are not supported yet")
            val blockCount = file.size() / BLOCK_SIZE
            val out = ByteArrayOutputStream()
            var block = firstBlock
            var previous = 0
            var size = 0
            var hops = 0L
            do {
                if (block < 1 || block >= blockCount) throw DamagedBlobException("Block $block is outside the .blb file")
                if (++hops > blockCount) throw DamagedBlobException("Block chain of blob $id loops")
                val data = file.readAt(block.toLong() * BLOCK_SIZE, BLOCK_SIZE)
                if (data.getInt(0) != previous) throw DamagedBlobException("Block $block does not follow block $previous")
                if (previous == 0) {
                    if (data.getInt(10) != id) throw DamagedBlobException("Block $block is not the start of blob $id")
                    size = data.getInt(14)
                }
                val used = data.u16(8)
                if (used > BLOCK_SIZE - BLOCK_DATA) throw DamagedBlobException("Block $block claims $used bytes")
                out.write(data.array(), BLOCK_DATA, used)
                previous = block
                block = data.getInt(4)
            } while (block != 0)
            if (out.size() != size) throw DamagedBlobException("Blob $id has ${out.size()} bytes, expected $size")
            return out.toByteArray()
        }
    }

    companion object {
        /** Opens a .dat file, and the .blb file next to it when there is one. [password] is only used for encrypted tables. */
        @JvmStatic
        @JvmOverloads
        @Throws(IOException::class)
        fun open(dat: Path, password: String? = null): DbisamTable {
            val blb = dat.resolveSibling(dat.fileName.toString().substringBeforeLast('.') + ".blb")
            val rows = FileChannel.open(dat)
            try {
                return DbisamTable(rows, if (Files.exists(blb)) FileChannel.open(blb) else null, password)
            } catch (e: Exception) {
                rows.close()
                throw e
            }
        }
    }
}

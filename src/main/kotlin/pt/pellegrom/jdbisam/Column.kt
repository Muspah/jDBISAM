package pt.pellegrom.jdbisam

/** On-disk column type. [width] is the value size in a row; null means it depends on the declared column length. */
enum class ColumnType(internal val code: Int, internal val width: Int?) {
    STRING(0x0001, null),
    DATE(0x0002, 4),
    BLOB(0x0003, 8),
    BOOLEAN(0x0004, 2),
    SMALLINT(0x0005, 2),
    INTEGER(0x0006, 4),
    FLOAT(0x0007, 8),
    BCD(0x0008, 34),
    TIME(0x000A, 4),
    TIMESTAMP(0x000B, 8),
    LARGEINT(0x0012, 8),
    CURRENCY(0x1507, 8),
    MEMO(0x1603, 8),
    GRAPHIC(0x1A03, 8),
    AUTOINC(0x1D06, 4),
}

/** [offset] is where the column's null flag sits in a row; its value starts one byte later. */
data class Column(val position: Int, val name: String, val type: ColumnType, val offset: Int, val length: Int)

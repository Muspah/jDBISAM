package pt.pellegrom.jdbisam

import java.io.IOException
import java.nio.file.Path
import java.util.HexFormat
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val command = args.getOrNull(0)
    if (args.size != 2 || command !in setOf("schema", "csv")) {
        System.err.println("Usage: jdbisam schema|csv <table.dat>   (JDBISAM_PASSWORD for encrypted tables)")
        exitProcess(2)
    }
    try {
        DbisamTable.open(Path.of(args[1]), System.getenv("JDBISAM_PASSWORD")).use { if (command == "schema") printSchema(it) else printCsv(it) }
    } catch (e: IOException) {
        System.err.println("${args[1]}: ${e.message}")
        exitProcess(1)
    }
}

private fun printSchema(table: DbisamTable) {
    println("rows: ${table.declaredRowCount}, row size: ${table.rowSize}, modified: ${table.lastModified}, version: ${table.userVersion}")
    table.description?.let { println("description: $it") }
    table.columns.forEach { println("${it.position + 1}\t${it.name}\t${it.type}\toffset ${it.offset}\tlength ${it.length}") }
}

private fun printCsv(table: DbisamTable) {
    println(table.columns.joinToString(",") { quote(it.name) })
    table.rows().forEach { row ->
        println(table.columns.joinToString(",") { column -> quote(render(column, row[column])) })
    }
}

private fun render(column: Column, value: Any?): String = when (value) {
    null -> ""
    is DbisamTable.Blob -> try {
        if (column.type == ColumnType.MEMO) value.text() else HexFormat.of().formatHex(value.bytes())
    } catch (e: DamagedBlobException) {
        System.err.println("${column.name}: ${e.message}")
        ""
    }
    is ByteArray -> HexFormat.of().formatHex(value)
    else -> value.toString()
}

private fun quote(text: String) =
    if (text.any { it in ",\"\r\n" }) "\"" + text.replace("\"", "\"\"") + "\"" else text

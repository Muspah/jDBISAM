package pt.pellegrom.jdbisam

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.test.Test
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Reads every .dat under JDBISAM_TESTDATA and checks invariants only, so no data ends up in the repo.
 * Encrypted tables are read with JDBISAM_PASSWORD when set.
 * Skipped when JDBISAM_TESTDATA is not set: `JDBISAM_TESTDATA=testdata-private mvn test`
 */
class RealTablesTest {
    @Test
    fun `every table either reads cleanly or is refused with a reason`() {
        val root = System.getenv("JDBISAM_TESTDATA")
        assumeTrue(root != null, "JDBISAM_TESTDATA not set")
        val password = System.getenv("JDBISAM_PASSWORD")

        val tables = Files.walk(Path.of(root)).use { paths -> paths.filter { it.extension.equals("dat", true) }.toList() }
        assertTrue(tables.isNotEmpty(), "no .dat files under $root")

        val refused = mutableMapOf<String, Int>()
        var rows = 0L
        var blobs = 0L
        var damagedBlobs = 0L
        for (path in tables) {
            try {
                DbisamTable.open(path, password).use { table ->
                    val ids = HashSet<Int>()
                    for (row in table.rows()) {
                        rows++
                        assertTrue(ids.add(row.recordId), "$path: duplicate record id ${row.recordId}")
                        for (value in row.values()) {
                            if (value !is DbisamTable.Blob) continue
                            blobs++
                            try {
                                value.bytes()
                            } catch (e: DamagedBlobException) {
                                damagedBlobs++
                            }
                        }
                    }
                }
            } catch (e: DbisamFormatException) {
                refused.merge(e.message!!.replace(Regex("\\d+"), "N"), 1, Int::plus)
            }
        }
        println("${tables.size} tables, ${tables.size - refused.values.sum()} read, $rows rows, $blobs blobs ($damagedBlobs damaged), refused: $refused")
        val expected = setOf("Not a table: only N bytes") + if (password == null) setOf("Table is encrypted; a password is needed") else emptySet()
        assertTrue(expected.containsAll(refused.keys), "unexpected refusals: ${refused.keys - expected}")
    }
}

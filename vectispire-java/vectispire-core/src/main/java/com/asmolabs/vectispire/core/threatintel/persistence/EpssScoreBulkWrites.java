package com.asmolabs.vectispire.core.threatintel.persistence;

import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import java.util.List;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writing a generation of EPSS scores many rows to a statement.
 *
 * <p><b>Why not {@code saveAll}.</b> The KEV catalogue's first synchronisation, a few thousand rows
 * through per-row {@code merge}, was already slow; the EPSS file is some 380,000 rows. {@code
 * saveAll} on an entity with an assigned key selects each row before inserting it, and without a
 * driver option that rewrites batches (which MySQL and PostgreSQL each spell differently, and SQLite
 * has none of) every insert is a round trip. One {@code insert … values (…), (…), …} of {@value
 * #ROWS_PER_STATEMENT} rows is plain SQL every engine reads alike, and a batch of five thousand rows
 * is ten statements.
 */
public interface EpssScoreBulkWrites {

    /**
     * Rows per statement: 2,000 bind parameters, under every engine's ceiling — SQLite's default
     * build refuses a statement past 32,766, PostgreSQL's driver past 65,535.
     */
    int ROWS_PER_STATEMENT = 500;

    /** Inserts these scores under {@code generation}, in one transaction. */
    @Transactional
    void insertAll(long generation, List<EpssFile.Score> scores);
}

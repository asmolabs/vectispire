package com.asmolabs.vectispire.core.threatintel.persistence;

import java.time.Instant;
import java.util.List;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writing the KEV catalogue's new entries many rows to a statement.
 *
 * <p><b>Why not {@code saveAll}.</b> The catalogue's key is the CVE, assigned rather than generated,
 * so Spring Data takes every entity for an existing one and {@code merge}s it: one {@code select} and
 * then one {@code insert} per CVE. The first synchronisation of an installation writes the whole
 * catalogue, some 1,500 entries — 3,000 round trips inside the transaction that holds the sync row's
 * lock. One {@code insert … values (…), (…), …} of {@value #ROWS_PER_STATEMENT} rows is plain SQL every
 * engine reads alike, as the EPSS file's is ({@link EpssScoreBulkWrites}).
 *
 * <p>An entry already stored — flagged again, or delisted — is still written by the entity it was
 * read as: those are a handful per synchronisation.
 */
public interface ThreatIntelBulkWrites {

    /**
     * Rows per statement: 2,000 bind parameters, under every engine's ceiling — SQLite's default
     * build refuses a statement past 32,766, PostgreSQL's driver past 65,535.
     */
    int ROWS_PER_STATEMENT = 500;

    /**
     * An entry the catalogue lists that is not stored yet.
     *
     * @param cveId upper-case, as the catalogue is stored
     * @param dateAdded the day CISA listed it; null when the catalogue did not say
     */
    record Listing(String cveId, Instant dateAdded) {}

    /** Inserts these entries as listed, in the caller's transaction — none of them may be stored already. */
    @Transactional
    void insertListed(List<Listing> listings, Instant updatedAt);
}

package com.asmolabs.vectispire.core.scanning.persistence.queries;

import java.time.Instant;

/**
 * A repository's newest completed scan in which one built-in step produced — what a checklist's
 * measurement cites as its evidence (decision 0032, §6).
 *
 * <p>Only a scan that <b>recorded</b> the type as examined is one: a scan from before {@code
 * examined_types} existed never is, whatever it found, because nothing says whether its step ran. A
 * repository with no such row is "never examined" or "unrecorded", which the reader tells apart — this
 * record never stands for either.
 *
 * <p>Top-level for the reason {@link LatestScanRow} gives: a JPQL {@code new} cannot name a nested type.
 *
 * @param createdAt when the scan was queued, the instant every other screen dates a scan by
 * @param sbomStored whether the scan still holds its SBOM — a dependency rule asks it, and the
 *     payload's retention may have purged it; asked in the query so that no SBOM is loaded to learn it
 */
public record ExaminingScanRow(Long repositoryId, Long scanId, Instant createdAt, boolean sbomStored) {}

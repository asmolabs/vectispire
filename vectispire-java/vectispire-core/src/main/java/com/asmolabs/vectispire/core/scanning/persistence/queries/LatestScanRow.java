package com.asmolabs.vectispire.core.scanning.persistence.queries;

import java.time.Instant;

/**
 * The most recent scan of one target, as the rollup queries return it.
 *
 * <p><b>A record instead of {@code Object[]}, and it is not about elegance.</b> Three files
 * unpacked these five columns by position — {@code ((Number) row[0]).longValue()},
 * {@code (String) row[2]}, {@code (Instant) row[3]}. Adding a column to the {@code select} shifts
 * every index after it and nothing fails to compile: the casts still type-check. The first sign
 * is a {@code ClassCastException}, or worse a value read from the neighbouring column that
 * happens to have the same type — a repository list showing another target's scan status, which
 * would not look like a bug in a query.
 *
 * <p>Hibernate builds this through a constructor expression, so a {@code select} that stops
 * matching stops the application at startup rather than at the first page load.
 *
 * <p><b>Top-level rather than nested</b> inside a holder class, for a blunt reason: Hibernate
 * cannot resolve a nested type from the dotted name in a JPQL {@code new} expression, and the
 * failure is a context that will not start.
 *
 * @param targetId the repository or the image, depending on which query produced this
 * @param status the stored wire name and not the enum — a value this version does not recognise
 *     has to reach the caller so it can decide what to do, and converting here would decide for it
 */
public record LatestScanRow(Long targetId, Long scanId, String status, Instant createdAt, String error) {}

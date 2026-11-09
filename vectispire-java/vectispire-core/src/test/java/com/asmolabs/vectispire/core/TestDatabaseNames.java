package com.asmolabs.vectispire.core;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The names {@link TestDatabase} gives its databases, and which of them a sweep may drop.
 *
 * <p><b>The creation instant is in the name because MySQL keeps it nowhere else.</b> {@code
 * information_schema.SCHEMATA} has no creation time, and a database's directory's mtime moves with
 * every table created in it. A server somebody keeps — a reused container, the one {@code
 * VECTISPIRE_TEST_DB_URL} names — collects the database of every JVM that was killed before its
 * shutdown hook ran; the name is what lets the next JVM tell an orphan from a run in progress.
 *
 * <p><b>Only a name that proves it is ours is ever swept</b>: the prefix, a kind this class gives,
 * an epoch-seconds instant and the sixteen hex digits of the random part, nothing before or after.
 * {@code vectispire} — the database {@code docker-compose.yml} creates — or a developer's {@code
 * vectispire_test} does not match, and neither does the earlier form without an instant, which no
 * sweep can date.
 */
final class TestDatabaseNames {

    /**
     * Far longer than any run, so a database a live JVM is using is never taken for an orphan: the
     * whole build runs in minutes, and a JVM stopped at a breakpoint overnight is the case it allows.
     */
    static final Duration ORPHANED_AFTER = Duration.ofHours(24);

    /** The JVM's database, migrated once and shared by its contexts. */
    static final String SHARED = "test";

    /** A database of one test's own, migrated from nothing. */
    static final String SCRATCH = "scratch";

    private static final Pattern OURS =
            Pattern.compile("vectispire_(?:" + SHARED + "|" + SCRATCH + ")_(\\d{1,12})_[0-9a-f]{16}");

    private TestDatabaseNames() {}

    /** {@code vectispire_<kind>_<epochSeconds>_<16 hex>}: 46 characters at most, under MySQL's 64. */
    static String name(String kind, Instant createdAt, long random) {
        return "vectispire_" + kind + "_" + createdAt.getEpochSecond() + "_" + HexFormat.of().toHexDigits(random);
    }

    /** When a database of ours was created; empty for any other name. */
    static Optional<Instant> createdAt(String name) {
        Matcher matcher = OURS.matcher(name);
        return matcher.matches() ? Optional.of(Instant.ofEpochSecond(Long.parseLong(matcher.group(1)))) : Optional.empty();
    }

    /**
     * The databases a sweep drops: ours, and created more than {@link #ORPHANED_AFTER} before {@code
     * now}. An instant in the future — a clock that moved back — is not old.
     */
    static List<String> orphans(Collection<String> names, Instant now) {
        Instant cutoff = now.minus(ORPHANED_AFTER);
        return names.stream()
                .filter(name -> createdAt(name).filter(created -> created.isBefore(cutoff)).isPresent())
                .sorted()
                .toList();
    }
}

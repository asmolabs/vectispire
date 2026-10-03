package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The sweep of a reused server drops what a killed JVM left, and nothing else: a database another
 * worktree's run is migrating right now, the composition's {@code vectispire}, or a name that only
 * looks like ours would each be a run failing for a reason nobody could trace.
 */
class TestDatabaseNamesTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    @Test
    void aNameCarriesTheInstantItWasCreatedAt() {
        String name = TestDatabaseNames.name(TestDatabaseNames.SHARED, NOW, 0x0123456789abcdefL);

        assertThat(name).isEqualTo("vectispire_test_" + NOW.getEpochSecond() + "_0123456789abcdef");
        assertThat(TestDatabaseNames.createdAt(name)).contains(NOW);
        assertThat(TestDatabaseNames.createdAt(TestDatabaseNames.name(TestDatabaseNames.SCRATCH, NOW, -1L)))
                .contains(NOW);
        // MySQL refuses a database name past 64 characters.
        assertThat(TestDatabaseNames.name(TestDatabaseNames.SCRATCH, Instant.ofEpochSecond(999_999_999_999L), -1L))
                .hasSizeLessThanOrEqualTo(64);
    }

    @Test
    void onlyANameOfOursIsDated() {
        assertThat(List.of(
                        "vectispire",
                        "vectispire_test",
                        "vectispire_test_0123456789abcdef",
                        "vectispire_other_1700000000_0123456789abcdef",
                        "vectispire_test_1700000000_0123456789abcde",
                        "vectispire_test_1700000000_0123456789ABCDEF",
                        "vectispire_test_1700000000_0123456789abcdef_copy",
                        "copy_vectispire_test_1700000000_0123456789abcdef",
                        "vectispire_test_17000000x0_0123456789abcdef"))
                .allSatisfy(name -> assertThat(TestDatabaseNames.createdAt(name)).as(name).isEmpty());
    }

    @Test
    void theSweepDropsOursOnceADayOldAndNothingElse() {
        String orphan = TestDatabaseNames.name(TestDatabaseNames.SHARED, NOW.minus(Duration.ofHours(25)), 1);
        String orphanScratch = TestDatabaseNames.name(TestDatabaseNames.SCRATCH, NOW.minus(Duration.ofDays(9)), 2);
        String running = TestDatabaseNames.name(TestDatabaseNames.SHARED, NOW.minus(Duration.ofHours(23)), 3);
        String justStarted = TestDatabaseNames.name(TestDatabaseNames.SCRATCH, NOW, 4);
        String atTheThreshold = TestDatabaseNames.name(TestDatabaseNames.SHARED, NOW.minus(Duration.ofHours(24)), 5);
        String fromAClockAhead = TestDatabaseNames.name(TestDatabaseNames.SHARED, NOW.plus(Duration.ofDays(3)), 6);

        assertThat(TestDatabaseNames.orphans(
                        List.of(running, orphan, "vectispire", "vectispire_test_0123456789abcdef", justStarted,
                                orphanScratch, atTheThreshold, fromAClockAhead, "mysql", "performance_schema"),
                        NOW))
                .containsExactlyInAnyOrder(orphan, orphanScratch);
    }
}

package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.owasp.CoverageWeek;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyHistoryService.OwaspWeek;
import com.asmolabs.vectispire.core.compliance.internal.OwaspWeeklyRetentionTask;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageEntity;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The weekly OWASP record, purged by the evidence window, against a database.
 *
 * <p>The boundary is a week's end, not its start: a week stays while any of it lies inside the window,
 * so that the oldest days the window promises are still recorded. The cases below put a cutoff just
 * either side of a week's end, which is where a {@code <=} for a {@code <}, or the week's start for its
 * end, would show.
 */
@DisplayName("the weekly OWASP record's retention, against a database")
class OwaspWeeklyRetentionDatabaseTest extends VectispireContextTest {

    /** Monday 18 August 2025; its week ends at Monday 25 August, 00:00 UTC. */
    private static final Instant EARLIER = Instant.parse("2025-08-18T00:00:00Z");
    private static final Instant WEEK = Instant.parse("2025-08-25T00:00:00Z");
    private static final Instant LATER = Instant.parse("2025-09-01T00:00:00Z");

    @Autowired
    private OwaspWeeklyCoverageService weekly;

    @Autowired
    private OwaspWeeklyRetentionTask task;

    @Autowired
    private OwaspWeeklyHistoryService history;

    @Autowired
    private OwaspWeeklyCoverageRepository rows;

    @Autowired
    private SettingsService settings;

    @Autowired
    private GitRepositoryRepository repositories;

    private long alpha;

    @BeforeEach
    void seed() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/alpha.git");
        entity.setName("alpha");
        entity.setBranch("main");
        alpha = repositories.save(entity).getId();
    }

    @Test
    @DisplayName("keeps the week the cutoff falls in, and removes the one that ended before it")
    void theWeekOfTheCutoffStays() {
        record(EARLIER);
        record(WEEK);
        record(LATER);

        // A Wednesday: Monday and Tuesday of its week are outside the window, the rest is inside.
        int purged = weekly.purgeEndedBefore(Instant.parse("2025-08-27T10:00:00Z"));

        assertThat(purged).isEqualTo(2);
        assertThat(weeksLeft()).containsExactlyInAnyOrder(WEEK, LATER);
    }

    @Test
    @DisplayName("a week that ended exactly at the cutoff goes; a microsecond earlier, it stays")
    void theBoundaryIsTheWeeksEnd() {
        record(EARLIER);
        record(WEEK);

        assertThat(weekly.purgeEndedBefore(WEEK.minus(Duration.ofNanos(1_000))))
                .as("its last microsecond is still inside the window")
                .isZero();
        assertThat(weeksLeft()).containsExactlyInAnyOrder(EARLIER, WEEK);

        assertThat(weekly.purgeEndedBefore(WEEK)).isEqualTo(2);
        assertThat(weeksLeft()).containsExactly(WEEK);

        assertThat(weekly.purgeEndedBefore(WEEK)).as("run again, nothing more goes").isZero();
    }

    @Test
    @DisplayName("the task reads evidence_retention_days, and zero keeps the record for ever")
    void theTaskReadsTheDial() {
        Instant now = Instant.now();
        // Well inside a thirty-day window, and well outside it: the clock the task reads moves on
        // between here and its run, and neither week is near enough the cutoff for that to matter.
        Instant inside = CoverageWeek.startOf(now.minus(Duration.ofDays(23)));
        Instant outside = CoverageWeek.startOf(now.minus(Duration.ofDays(30))).minus(Duration.ofDays(7));
        Instant ancient = Instant.parse("2020-01-06T00:00:00Z");
        record(ancient);
        record(outside);
        record(inside);

        settings.set(Setting.EVIDENCE_RETENTION_DAYS, "0");
        task.run();
        assertThat(weeksLeft()).as("zero purges nothing").containsExactlyInAnyOrder(ancient, outside, inside);

        settings.set(Setting.EVIDENCE_RETENTION_DAYS, "30");
        task.run();
        assertThat(weeksLeft()).containsExactly(inside);
    }

    @Test
    @DisplayName("a purged week is answered as reconstructed; a kept one still as recorded")
    void aPurgedWeekIsReconstructed() {
        Instant now = Instant.now();
        Instant inside = CoverageWeek.startOf(now.minus(Duration.ofDays(23)));
        Instant outside = CoverageWeek.startOf(now.minus(Duration.ofDays(30))).minus(Duration.ofDays(7));
        record(outside);
        record(inside);
        assertThat(week(outside).reconstructed()).as("recorded before the purge").isFalse();

        settings.set(Setting.EVIDENCE_RETENTION_DAYS, "30");
        task.run();

        OwaspWeek purged = week(outside);
        assertThat(purged.reconstructed()).isTrue();
        assertThat(purged.capturedAt()).isNull();
        assertThat(purged.settled()).isNull();
        assertThat(purged.categories()).allSatisfy(line -> assertThat(line.state()).isNull());
        assertThat(week(inside).reconstructed()).isFalse();
    }

    private OwaspWeek week(Instant monday) {
        String day = LocalDate.ofInstant(monday, ZoneOffset.UTC).toString();
        return history.weeks(
                        new OwaspWeeklyHistoryService.Request(day, day, null, null),
                        new VisibilityService.Allowance(Visibility.everything(), Set.of()))
                .weeks()
                .getFirst();
    }

    private List<Instant> weeksLeft() {
        return rows.findAll().stream().map(OwaspWeeklyCoverageEntity::getWeekStart).distinct().toList();
    }

    /** One week of {@code alpha}'s record: two categories, so a purge counts rows, not weeks. */
    private void record(Instant monday) {
        for (String category : new String[] {"A03", "A06"}) {
            OwaspWeeklyCoverageEntity row = new OwaspWeeklyCoverageEntity();
            row.setWeekStart(monday);
            row.setTargetKind("repository");
            row.setTargetId(alpha);
            row.setCategory(category);
            row.setState(OwaspCoverage.State.NO_FINDING.name());
            row.setCapturedAt(monday.plus(Duration.ofDays(2)));
            rows.save(row);
        }
    }
}

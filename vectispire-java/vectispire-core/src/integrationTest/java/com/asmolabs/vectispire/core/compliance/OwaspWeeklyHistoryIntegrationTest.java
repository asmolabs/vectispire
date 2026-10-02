package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageOrigin;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyHistoryService.OwaspWeek;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyHistoryService.OwaspWeekCategory;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageEntity;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.issues.IssueQueryService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.LongStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The weekly OWASP view's reads on a real engine: the reconstruction's conditional sums over bound
 * instants, the record summed per week and state, the backlog's date filters, and the instant Flyway's
 * history holds for V68 — read natively, its type each driver's own.
 *
 * <p><b>What the engines could disagree on</b>: a {@code sum(case …)} over timestamp parameters, which
 * each driver binds its own way (MySQL's {@code datetime(6)} carries no zone); the half-open boundaries,
 * where a timestamp rounded by a column type would move an issue from one week to the next; the
 * aggregates' numeric types. Every instant here sits on a boundary or a second from one.
 *
 * <p><b>A reader wider than one statement can bind</b>: seventy thousand targets, past the PostgreSQL
 * driver's 65,535 parameters. Both reads write the identifiers into the statement, so the limit is
 * PostgreSQL's alone to prove; on MySQL the case checks the narrowing itself.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the weekly OWASP view's reads, on a real engine")
class OwaspWeeklyHistoryIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant WEEK = Instant.parse("2025-03-03T00:00:00Z");
    private static final Instant NEXT_WEEK = Instant.parse("2025-03-10T00:00:00Z");
    private static final Instant EARLIER = Instant.parse("2025-02-01T00:00:00Z");

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private OwaspWeeklyHistoryService weekly;

    @Autowired
    private OwaspWeeklyCoverageRepository records;

    @Autowired
    private IssueQueryService backlog;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TriageEventRepository events;

    @Autowired
    private JdbcTemplate jdbc;

    private long mine;
    private long theirs;
    private long resolvedAtTheEnd;

    @BeforeEach
    void aBacklogOnTheBoundaries() {
        records.deleteAll();
        events.deleteAll();
        issues.deleteAll();
        repositories.deleteAll();
        mine = repository("mine");
        theirs = repository("theirs");

        issue(mine, FindingType.VULNERABILITY, null, WEEK, null);
        issue(mine, FindingType.SECRET, null, NEXT_WEEK, null);
        resolvedAtTheEnd = issue(mine, FindingType.VULNERABILITY, null, EARLIER, NEXT_WEEK);
        issue(mine, FindingType.VULNERABILITY, null, EARLIER, NEXT_WEEK.minusSeconds(1));
        issue(mine, FindingType.SAST, "A03", Instant.parse("2025-03-05T12:00:00Z"), null);
        issue(theirs, FindingType.VULNERABILITY, null, EARLIER, null);
    }

    @Test
    @DisplayName("reconstructs open, opened and resolved at the weeks' exact boundaries")
    void reconstructs() {
        List<OwaspWeek> weeks = weekly.weeks(
                new OwaspWeeklyHistoryService.Request("2025-03-03", "2025-03-10", null, null), everything()).weeks();

        assertThat(weeks).allSatisfy(week -> assertThat(week.reconstructed()).isTrue());
        assertThat(counts(weeks.get(0), "A06")).containsExactly(3L, 1L, 1L);
        assertThat(counts(weeks.get(0), "A07")).containsExactly(0L, 0L, 0L);
        assertThat(counts(weeks.get(0), "A03")).containsExactly(1L, 1L, 0L);
        assertThat(counts(weeks.get(1), "A06")).containsExactly(2L, 0L, 1L);
        assertThat(counts(weeks.get(1), "A07")).containsExactly(1L, 1L, 0L);
        assertThat(line(weeks.get(0), "A06").state()).isNull();
        assertThat(line(weeks.get(0), "A06").settled()).isNull();
    }

    @Test
    @DisplayName("an earlier resolution a reopening recorded: not open, its week's resolution — a correlated subquery in each sum")
    void anEarlierResolution() {
        long reopened = issue(mine, FindingType.VULNERABILITY, null, EARLIER, null);
        TriageEventEntity reopening = new TriageEventEntity();
        reopening.setIssueId(reopened);
        reopening.setFromStatus(TriageStatus.FIXED.wireName());
        reopening.setToStatus(TriageStatus.UNDER_REVIEW.wireName());
        reopening.setOrigin(TriageOrigin.REOPENING.wireName());
        // Resolved a second before the week's end, found again at the next week's end: on both
        // boundaries a timestamp rounded by a column type would move it.
        reopening.setPreviousResolvedAt(NEXT_WEEK.minusSeconds(1));
        reopening.setOccurredAt(NEXT_WEEK.plusSeconds(7 * 86_400));
        events.save(reopening);

        List<OwaspWeek> weeks = weekly.weeks(
                new OwaspWeeklyHistoryService.Request("2025-03-03", "2025-03-17", null, null), everything()).weeks();
        assertThat(counts(weeks.get(0), "A06")).as("the setup's three, and not this one").containsExactly(3L, 1L, 2L);
        assertThat(counts(weeks.get(1), "A06")).containsExactly(2L, 0L, 1L);
        assertThat(counts(weeks.get(2), "A06")).as("open again").containsExactly(3L, 0L, 0L);

        assertThat(listed(query("A06", "2025-03-16", null, null, null, null))).doesNotContain(reopened).hasSize(2);
        assertThat(listed(query("A06", "2025-03-17", null, null, null, null))).contains(reopened).hasSize(3);
        assertThat(listed(query(null, null, null, null, "2025-03-09", "2025-03-09"))).contains(reopened).hasSize(2);
    }

    @Test
    @DisplayName("reopened: a fourth correlated sum on the boundaries, null before Flyway's V68, and the lists it opens")
    void reopened() {
        long boundary = issue(mine, FindingType.VULNERABILITY, null, EARLIER, null);
        reopening(boundary, NEXT_WEEK);
        long lastSecond = issue(mine, FindingType.SAST, "A03", EARLIER, null);
        reopening(lastSecond, NEXT_WEEK.minusSeconds(1));
        reopening(issue(mine, FindingType.QUALITY, null, EARLIER, null), NEXT_WEEK.minusSeconds(1));

        OwaspWeeklyHistoryService.Request march = new OwaspWeeklyHistoryService.Request("2025-03-03", "2025-03-10", null, null);
        assertThat(weekly.weeks(march, everything()).weeks()).as("V68 applied by this run, after these weeks")
                .allSatisfy(week -> assertThat(week.reopened()).isNull());

        java.sql.Timestamp applied = jdbc.queryForObject(
                "select installed_on from flyway_schema_history where version = '68'", java.sql.Timestamp.class);
        jdbc.update("update flyway_schema_history set installed_on = ? where version = '68'",
                java.sql.Timestamp.valueOf("2025-01-01 00:00:00"));
        try {
            OwaspWeeklyHistoryService.OwaspWeeklyCoverage answer = weekly.weeks(march, everything());
            assertThat(answer.reopenedRecordedFrom()).hasToString("2025-01-06");
            List<OwaspWeek> weeks = answer.weeks();
            assertThat(line(weeks.get(0), "A03").reopened()).as("a second before the week's end").isEqualTo(1);
            assertThat(line(weeks.get(0), "A06").reopened()).isZero();
            assertThat(line(weeks.get(1), "A06").reopened()).as("at the next Monday's midnight").isEqualTo(1);
            assertThat(weeks.get(0).reopened()).as("a quality finding is in no category").isEqualTo(1);

            assertThat(listed(reopenedQuery("any", "2025-03-03", "2025-03-09"))).containsExactly(lastSecond);
            assertThat(listed(reopenedQuery("any", "2025-03-10", "2025-03-16"))).containsExactly(boundary);
            assertThat(listed(reopenedQuery(null, "2025-03-03", "2025-03-09"))).hasSize(2);
        } finally {
            jdbc.update("update flyway_schema_history set installed_on = ? where version = '68'", applied);
        }
    }

    @Test
    @DisplayName("owasp_category=any lists what some category holds, and the week's total opened is its length")
    void anyCategory() {
        issue(mine, FindingType.LICENSE, null, Instant.parse("2025-03-05T12:00:00Z"), null);
        issue(mine, FindingType.SAST, null, Instant.parse("2025-03-05T12:00:00Z"), null);
        issue(mine, FindingType.SAST, "A11", Instant.parse("2025-03-05T12:00:00Z"), null);
        OwaspWeek week = weekly.weeks(
                new OwaspWeeklyHistoryService.Request("2025-03-03", "2025-03-03", null, null), everything()).weeks().getFirst();

        assertThat(listed(query("any", null, "2025-03-03", "2025-03-09", null, null))).hasSize((int) week.opened()).hasSize(2);
        assertThat(listed(query("any", "2025-03-09", null, null, null, null))).hasSize((int) week.open());
    }

    @Test
    @DisplayName("a year of weeks reads in several statements and agrees with a week read alone")
    void aYear() {
        List<OwaspWeek> year = weekly.weeks(
                new OwaspWeeklyHistoryService.Request("2024-06-03", "2025-05-26", null, null), everything()).weeks();
        List<OwaspWeek> alone = weekly.weeks(
                new OwaspWeeklyHistoryService.Request("2025-03-10", "2025-03-10", null, null), everything()).weeks();

        assertThat(year).hasSize(52);
        OwaspWeek march = year.stream().filter(week -> week.weekStart().toString().equals("2025-03-10")).findFirst().orElseThrow();
        assertThat(march.categories()).isEqualTo(alone.getFirst().categories());
        assertThat(year.getLast().categories().stream().filter(line -> line.category().equals("A06")).findFirst()
                .orElseThrow().open()).as("still open at the year's end").isEqualTo(2);
    }

    @Test
    @DisplayName("a recorded week is summed per category and state over the reader's targets — wider than a statement binds")
    void aRecordedWeekForAWideReader() {
        record(mine, "A06", OwaspCoverage.State.FINDINGS, 2, 1);
        record(theirs, "A06", OwaspCoverage.State.FINDINGS, 5, 0);
        record(mine, "A07", OwaspCoverage.State.NO_FINDING, 0, 0);
        record(theirs, "A07", OwaspCoverage.State.NOT_MEASURED, 0, 0);

        List<ScanTarget> wide = new ArrayList<>(LongStream.rangeClosed(9_000_000, 9_070_000)
                .<ScanTarget>mapToObj(ScanTarget.Repository::new).toList());
        wide.add(new ScanTarget.Repository(mine));
        VisibilityService.Allowance reader = new VisibilityService.Allowance(Visibility.only(wide), Set.of());

        OwaspWeek week = weekly.weeks(new OwaspWeeklyHistoryService.Request("2025-03-03", "2025-03-03", null, null), reader)
                .weeks().getFirst();
        assertThat(week.reconstructed()).isFalse();
        assertThat(line(week, "A06")).returns(OwaspCoverage.State.FINDINGS, OwaspWeekCategory::state)
                .returns(2L, OwaspWeekCategory::open)
                .returns(1L, OwaspWeekCategory::settled)
                .returns(1L, OwaspWeekCategory::opened);
        assertThat(line(week, "A07").state()).isEqualTo(OwaspCoverage.State.NO_FINDING);

        OwaspWeek everybody = weekly.weeks(
                new OwaspWeeklyHistoryService.Request("2025-03-03", "2025-03-03", null, null), everything()).weeks().getFirst();
        assertThat(line(everybody, "A06").open()).isEqualTo(7);
        assertThat(line(everybody, "A06").opened()).isEqualTo(1);
    }

    @Test
    @DisplayName("the backlog's open_at lists a since-resolved issue, and its date ranges hold at the boundaries")
    void theDrillDown() {
        assertThat(listed(query("A06", "2025-03-09", null, null, null, null)))
                .hasSize(3)
                .contains(resolvedAtTheEnd);
        assertThat(listed(query(null, null, null, null, "2025-03-10", "2025-03-10"))).containsExactly(resolvedAtTheEnd);
        assertThat(listed(query(null, null, "2025-03-10", "2025-03-16", null, null))).hasSize(1);
    }

    private static VisibilityService.Allowance everything() {
        return new VisibilityService.Allowance(Visibility.everything(), Set.of());
    }

    private static IssueQueryService.BacklogQuery query(
            String category, String openAt, String firstSeenFrom, String firstSeenTo, String resolvedFrom, String resolvedTo) {
        return new IssueQueryService.BacklogQuery(null, null, null, null, null, null, null, null, false, false, false,
                false, null, 500, 0, category, openAt, firstSeenFrom, firstSeenTo, resolvedFrom, resolvedTo, null, null);
    }

    private static IssueQueryService.BacklogQuery reopenedQuery(String category, String from, String to) {
        return new IssueQueryService.BacklogQuery(null, null, null, null, null, null, null, null, false, false, false,
                false, null, 500, 0, category, null, null, null, null, null, from, to);
    }

    private void reopening(long issueId, Instant at) {
        TriageEventEntity reopening = new TriageEventEntity();
        reopening.setIssueId(issueId);
        reopening.setFromStatus(TriageStatus.UNDER_REVIEW.wireName());
        reopening.setToStatus(TriageStatus.UNDER_REVIEW.wireName());
        reopening.setOrigin(TriageOrigin.REOPENING.wireName());
        reopening.setPreviousResolvedAt(at.minusSeconds(86_400));
        reopening.setOccurredAt(at);
        events.save(reopening);
    }

    private List<Long> listed(IssueQueryService.BacklogQuery query) {
        return backlog.page(query, Visibility.everything()).items().stream().map(entry -> entry.issue().id()).toList();
    }

    private static List<Long> counts(OwaspWeek week, String category) {
        OwaspWeekCategory line = line(week, category);
        return List.of(line.open(), line.opened(), line.resolved());
    }

    private static OwaspWeekCategory line(OwaspWeek week, String category) {
        return week.categories().stream().filter(line -> line.category().equals(category)).findFirst().orElseThrow();
    }

    private void record(long repoId, String category, OwaspCoverage.State state, long open, long settled) {
        OwaspWeeklyCoverageEntity row = new OwaspWeeklyCoverageEntity();
        row.setWeekStart(WEEK);
        row.setTargetKind("repository");
        row.setTargetId(repoId);
        row.setCategory(category);
        row.setState(state.name());
        row.setOpenCount(open);
        row.setSettledCount(settled);
        row.setCapturedAt(Instant.parse("2025-03-08T18:00:00Z"));
        records.save(row);
    }

    private long repository(String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/" + name + "-" + System.nanoTime() + ".git");
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long issue(long repoId, FindingType type, String owaspCategory, Instant firstSeen, Instant resolved) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier("rule-" + System.nanoTime());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setOwaspCategory(owaspCategory);
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(firstSeen);
        issue.setLastSeenAt(firstSeen);
        issue.setTimesSeen(1);
        if (resolved != null) {
            issue.resolveAt(resolved);
        }
        return issues.save(issue).getId();
    }
}

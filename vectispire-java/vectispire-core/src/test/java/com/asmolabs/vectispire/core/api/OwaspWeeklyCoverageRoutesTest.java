package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageOrigin;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.owasp.CoverageWeek;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyCoverageService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@code GET /api/v1/owasp/coverage/weekly}, and the backlog's filters its figures open.
 *
 * <p>The cases pin what the screen built on this route depends on: the recorded week agrees with the
 * live grid beside it, a past week is reconstructed from dates at exact boundaries and says so, a
 * reader sees the sum of their targets and no more, a scope hidden from them reads as an absent one,
 * and every figure leads to a list holding what it counted — a since-resolved issue included.
 */
@DisplayName("the weekly OWASP coverage, and the drill-down to the backlog")
class OwaspWeeklyCoverageRoutesTest extends ApiTestBase {

    /** A Monday long past: the weeks of these cases are reconstructed, nothing having captured them. */
    private static final Instant WEEK = Instant.parse("2025-03-03T00:00:00Z");
    private static final Instant NEXT_WEEK = Instant.parse("2025-03-10T00:00:00Z");
    private static final Instant EARLIER = Instant.parse("2025-02-01T00:00:00Z");

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private SettingsService settings;

    @Autowired
    private OwaspWeeklyCoverageService record;

    @Autowired
    private TriageEventRepository events;

    @Autowired
    private JdbcTemplate jdbc;

    // ------------------------------------------------------------------------------ the recorded week

    @Test
    @DisplayName("the current week, once recorded, reads what the live grid reads — state and open, category by category")
    void theCurrentWeekIsTheLiveGrid() throws Exception {
        anEstate();
        aNeverScannedTarget();
        assertThat(record.capture()).isEqualTo(OwaspWeeklyCoverageService.Outcome.CAPTURED);

        JsonNode current = lastWeek(weekly("", asAdmin()));
        assertThat(current.path("reconstructed").asBoolean()).isFalse();
        assertThat(current.path("weekStart").asText())
                .isEqualTo(LocalDate.ofInstant(CoverageWeek.startOf(Instant.now()), ZoneOffset.UTC).toString());
        assertSameAsTheGrid(current, grid(asAdmin()));
        assertThat(category(current, "A06").path("settled").asLong())
                .as("the accepted vulnerability, kept apart").isEqualTo(1);
        assertThat(category(current, "A06").path("open").asLong())
                .as("alpha's, beta's and the never-scanned gamma's, as the grid counts them").isEqualTo(3);
        assertThat(category(current, "A05").path("settled").asLong()).as("gamma's accepted misconfiguration").isEqualTo(1);
        JsonNode secrets = category(current, "A07");
        assertThat(List.of(secrets.path("state").asText(), secrets.path("open").asLong(), secrets.path("settled").asLong()))
                .as("findings on beta, clean on alpha; an accepted secret on each")
                .containsExactly("FINDINGS", 1L, 2L);
        assertThat(current.path("capturedAt").isNull()).isFalse();
    }

    @Test
    @DisplayName("a restricted reader's week is the sum of their targets — and still the grid they are shown")
    void aRestrictedReaderSumsTheirTargets() throws Exception {
        Estate estate = anEstate();
        restrict();
        String reader = asReader();
        grant(readerId(), "repository", estate.alpha());
        record.capture();

        JsonNode mine = lastWeek(weekly("", reader));
        assertThat(category(mine, "A06").path("open").asLong()).as("alpha's open vulnerability, not beta's").isEqualTo(1);
        assertThat(category(mine, "A05").path("open").asLong()).as("beta's misconfiguration is not theirs").isZero();
        assertSameAsTheGrid(mine, grid(reader));

        JsonNode all = lastWeek(weekly("", asAdmin()));
        assertThat(category(all, "A06").path("open").asLong()).isEqualTo(2);
    }

    @Test
    @DisplayName("a never-scanned target counts beside a scanned one, and nowhere when the reader sees only it — as in the grid")
    void aNeverScannedTargetCountsAsTheGridCountsIt() throws Exception {
        Estate estate = anEstate();
        long gamma = aNeverScannedTarget();
        restrict();
        String reader = asReader();
        record.capture();

        grant(readerId(), List.of(gamma));
        JsonNode alone = lastWeek(weekly("", reader));
        assertSameAsTheGrid(alone, grid(reader));
        assertThat(List.of(category(alone, "A05").path("state").asText(), category(alone, "A05").path("open").asLong()))
                .as("nothing the reader sees was scanned: not measured, its findings not counted")
                .containsExactly("NOT_MEASURED", 0L);

        grant(readerId(), List.of(estate.alpha(), gamma));
        JsonNode beside = lastWeek(weekly("", reader));
        assertSameAsTheGrid(beside, grid(reader));
        assertThat(List.of(category(beside, "A05").path("state").asText(), category(beside, "A05").path("open").asLong()))
                .as("alpha scanned and clean, gamma's misconfiguration counted").containsExactly("FINDINGS", 1L);
        assertThat(category(beside, "A06").path("open").asLong()).as("alpha's and gamma's").isEqualTo(2);
    }

    // ------------------------------------------------------------------------------ the past, reconstructed

    @Test
    @DisplayName("a past week is reconstructed from dates, at its exact boundaries, and states neither state nor settled")
    void aPastWeekIsReconstructed() throws Exception {
        aBoundaryBacklog(repository());

        JsonNode weeks = weekly("from=2025-03-05&to=2025-03-12", asAdmin()).path("weeks");
        assertThat(weeks).hasSize(2);
        JsonNode week = weeks.get(0);
        JsonNode next = weeks.get(1);
        assertThat(week.path("weekStart").asText()).as("a Wednesday is read as its Monday").isEqualTo("2025-03-03");
        assertThat(next.path("weekStart").asText()).isEqualTo("2025-03-10");

        assertThat(week.path("reconstructed").asBoolean()).isTrue();
        assertThat(week.path("capturedAt").isNull()).isTrue();
        assertThat(week.path("settled").isNull()).isTrue();
        assertThat(week.path("categoriesMeasured").isNull()).isTrue();
        assertThat(category(week, "A06").path("state").isNull()).as("never computed now for then").isTrue();
        assertThat(category(week, "A06").path("settled").isNull()).isTrue();

        // Open at the end: seen at the week's first instant and still open, and resolved at the next
        // Monday's midnight — still open until then. Not the one resolved a second before it.
        assertThat(counts(week, "A06")).containsExactly(2L, 1L, 1L);
        // First seen at the next Monday's midnight: the next week's, not this one's.
        assertThat(counts(week, "A07")).containsExactly(0L, 0L, 0L);
        assertThat(counts(week, "A03")).as("code analysis, by its rule's declaration").containsExactly(1L, 1L, 0L);

        assertThat(counts(next, "A06")).containsExactly(1L, 0L, 1L);
        assertThat(counts(next, "A07")).containsExactly(1L, 1L, 0L);
        assertThat(next.path("open").asLong()).as("the week's total is its categories'").isEqualTo(3);
        assertThat(next.path("opened").asLong()).isEqualTo(1);
        assertThat(next.path("resolved").asLong()).isEqualTo(1);
        assertThat(week.path("opened").asLong())
                .as("an unplaced code finding and a plugin's are in no category, nor in the total")
                .isEqualTo(2);
    }

    @Test
    @DisplayName("an earlier resolution a reopening recorded is not open, and is its week's resolution — a reopening that recorded nothing reads as before")
    void anEarlierResolutionIsNotOpen() throws Exception {
        long repo = repository();
        Reopened backlog = aReopenedBacklog(repo);

        JsonNode weeks = weekly("from=2025-03-03&to=2025-03-17", asAdmin()).path("weeks");
        assertThat(counts(weeks.get(0), "A06"))
                .as("resolved mid-week and not reopened before the week's end: not open, and resolved this week")
                .containsExactly(1L, 0L, 1L);
        assertThat(counts(weeks.get(1), "A06"))
                .as("reopened at the next Monday's midnight: still resolved at this week's end")
                .containsExactly(1L, 0L, 0L);
        assertThat(counts(weeks.get(2), "A06")).as("open again").containsExactly(2L, 0L, 0L);

        assertThat(listed("open_at=2025-03-09&owasp_category=A06", asAdmin()))
                .as("the cell's list: the issue whose reopening recorded nothing, alone").containsExactly(backlog.unrecorded());
        assertThat(listed("open_at=2025-03-17&owasp_category=A06", asAdmin()))
                .containsExactlyInAnyOrder(backlog.unrecorded(), backlog.reopened());
        assertThat(listed("resolved_from=2025-03-03&resolved_to=2025-03-09", asAdmin()))
                .as("open today, and resolved that week").containsExactly(backlog.reopened());
        assertThat(listed("resolved_from=2025-03-10", asAdmin())).as("its resolution began before").isEmpty();
    }

    @Test
    @DisplayName("twelve weeks by default, ending with the current one; fifty-two at most")
    void theWindow() throws Exception {
        JsonNode defaults = weekly("", asAdmin());
        assertThat(defaults.path("weeks")).hasSize(12);
        assertThat(defaults.path("to").asText())
                .isEqualTo(LocalDate.ofInstant(CoverageWeek.startOf(Instant.now()), ZoneOffset.UTC).toString());
        assertThat(defaults.path("scope").isNull()).isTrue();

        assertThat(weekly("from=2024-01-01&to=2024-12-23", asAdmin()).path("weeks")).as("exactly 52").hasSize(52);
        assertThat(weekly("to=2999-01-01", asAdmin()).path("to").asText())
                .as("a week after the current one is the current one")
                .isEqualTo(defaults.path("to").asText());

        assertThat(refused("from=2024-01-01&to=2024-12-30", asAdmin()))
                .isEqualTo("At most 52 weeks per request; this one spans 53.");
        assertThat(refused("from=2025-03-10&to=2025-03-03", asAdmin())).isEqualTo("from comes after to.");
        assertThat(refused("from=last-monday", asAdmin())).isEqualTo("from must be an ISO date, YYYY-MM-DD: \"last-monday\".");
        assertThat(refused("project_id=1&solution_id=1", asAdmin())).isEqualTo("Name a project or a solution, not both.");
    }

    // ------------------------------------------------------------------------------ scopes

    @Test
    @DisplayName("a project's weeks count its targets only, and say which scope they are")
    void aProjectsWeeks() throws Exception {
        long project = project(solution(), "API");
        long filed = repository();
        long elsewhere = repository();
        file(project, filed);
        issue(filed, FindingType.VULNERABILITY, null, EARLIER, null);
        issue(elsewhere, FindingType.VULNERABILITY, null, EARLIER, null);

        JsonNode answer = weekly("from=2025-03-03&to=2025-03-03&project_id=" + project, asAdmin());
        assertThat(category(answer.path("weeks").get(0), "A06").path("open").asLong()).isEqualTo(1);
        assertThat(answer.path("scope").path("kind").asText()).isEqualTo("project");
        assertThat(answer.path("scope").path("name").asText()).isEqualTo("API");
        assertThat(answer.path("scope").path("targetCount").asInt()).isEqualTo(1);
    }

    @Test
    @DisplayName("a project or a solution the reader sees nothing of answers 404, in the words an absent one does")
    void aHiddenScopeIsAnAbsentOne() throws Exception {
        restrict();
        long solution = solution();
        long project = project(solution, "Secret");
        long secret = repository();
        file(project, secret);
        issue(secret, FindingType.VULNERABILITY, null, EARLIER, null);
        String reader = asReader();
        grant(readerId(), "repository", repository());

        MvcResult hidden = notFound("project_id=" + project, reader);
        MvcResult absent = notFound("project_id=" + Long.MAX_VALUE, reader);
        assertThat(detailOf(hidden)).isEqualTo(detailOf(absent)).isEqualTo("Project not found.");
        assertThat(detailOf(notFound("solution_id=" + solution, reader)))
                .isEqualTo(detailOf(notFound("solution_id=" + Long.MAX_VALUE, reader)));
    }

    // ------------------------------------------------------------------------------ reopened

    @Test
    @DisplayName("reopened counts a recorded reopening in its week and category, once per issue, and lists what it counted")
    void reopenedIsCountedAndListed() throws Exception {
        long repo = repository();
        long twice = issue(repo, FindingType.VULNERABILITY, null, EARLIER, null);
        reopening(twice, Instant.parse("2025-03-04T09:00:00Z"));
        reopening(twice, Instant.parse("2025-03-06T09:00:00Z"));
        long secret = issue(repo, FindingType.SECRET, null, EARLIER, null);
        reopening(secret, NEXT_WEEK);
        long licence = issue(repo, FindingType.LICENSE, null, EARLIER, null);
        reopening(licence, Instant.parse("2025-03-05T09:00:00Z"));
        long decided = issue(repo, FindingType.VULNERABILITY, null, EARLIER, null);
        TriageEventEntity decision = reopening(decided, Instant.parse("2025-03-05T09:00:00Z"));
        decision.setOrigin(TriageOrigin.MANUAL.wireName());
        events.save(decision);

        recordingReopeningsSince("2025-01-01 00:00:00", () -> {
            JsonNode answer = weekly("from=2025-03-03&to=2025-03-10", asAdmin());
            assertThat(answer.path("reopenedRecordedFrom").asText()).as("the first Monday a day after V68").isEqualTo("2025-01-06");
            JsonNode week = answer.path("weeks").get(0);
            assertThat(category(week, "A06").path("reopened").asLong())
                    .as("reopened twice that week, counted once; a decision is not a reopening").isEqualTo(1);
            assertThat(category(week, "A07").path("reopened").asLong()).as("at the next Monday's midnight: the next week's").isZero();
            assertThat(week.path("reopened").asLong()).as("a licence finding is in no category, nor in the total").isEqualTo(1);
            assertThat(category(answer.path("weeks").get(1), "A07").path("reopened").asLong()).isEqualTo(1);

            assertThat(listed("reopened_from=2025-03-03&reopened_to=2025-03-09&owasp_category=A06", asAdmin()))
                    .as("the cell's list").containsExactly(twice);
            assertThat(listed("reopened_from=2025-03-03&reopened_to=2025-03-09", asAdmin()))
                    .as("every state, and every type without a category").containsExactlyInAnyOrder(twice, licence);
            assertThat(listed("reopened_from=2025-03-10&reopened_to=2025-03-10", asAdmin())).containsExactly(secret);
        });
    }

    @Test
    @DisplayName("a week that began before reopenings were recorded answers no reopened figure — not zero")
    void reopenedIsUnknownBeforeItWasRecorded() throws Exception {
        long repo = repository();
        reopening(issue(repo, FindingType.VULNERABILITY, null, EARLIER, null), Instant.parse("2025-03-12T09:00:00Z"));
        reopening(issue(repo, FindingType.VULNERABILITY, null, EARLIER, null), Instant.parse("2025-03-19T09:00:00Z"));

        // Applied on the Sunday at noon: known from the Monday at noon, a day's margin later — so from
        // the Monday after, the week of the upgrade having begun before it.
        recordingReopeningsSince("2025-03-09 12:00:00", () -> {
            JsonNode answer = weekly("from=2025-03-03&to=2025-03-17", asAdmin());
            assertThat(answer.path("reopenedRecordedFrom").asText()).isEqualTo("2025-03-17");
            for (JsonNode before : List.of(answer.path("weeks").get(0), answer.path("weeks").get(1))) {
                assertThat(before.path("reopened").isNull()).as(before.path("weekStart").asText()).isTrue();
                assertThat(category(before, "A06").path("reopened").isNull()).isTrue();
                assertThat(category(before, "A06").path("opened").isNull()).as("the other flows still are figures").isFalse();
            }
            JsonNode after = answer.path("weeks").get(2);
            assertThat(after.path("reopened").asLong()).isEqualTo(1);
            assertThat(category(after, "A01").path("reopened").asLong()).as("known, and none").isZero();
        });
    }

    // ------------------------------------------------------------------------------ the week's total

    @Test
    @DisplayName("a week's total figures are the lengths of the lists owasp_category=any opens with the same dates")
    void theTotalsOpenTheirLists() throws Exception {
        long repo = repository();
        aBoundaryBacklog(repo);
        issue(repo, FindingType.LICENSE, null, Instant.parse("2025-03-05T12:00:00Z"), null);
        issue(repo, FindingType.QUALITY, "A03", Instant.parse("2025-03-05T12:00:00Z"), Instant.parse("2025-03-06T12:00:00Z"));
        reopening(issue(repo, FindingType.IAC, null, EARLIER, null), Instant.parse("2025-03-06T12:00:00Z"));
        reopening(issue(repo, FindingType.SAST, "A11", EARLIER, null), Instant.parse("2025-03-06T12:00:00Z"));

        recordingReopeningsSince("2025-01-01 00:00:00", () -> {
            for (JsonNode week : weekly("from=2025-03-03&to=2025-03-10", asAdmin()).path("weeks")) {
                LocalDate monday = LocalDate.parse(week.path("weekStart").asText());
                String days = monday + "&%s_to=" + monday.plusDays(6);
                assertThat(listed("owasp_category=any&first_seen_from=" + days.formatted("first_seen"), asAdmin()))
                        .as("opened, " + monday).hasSize(week.path("opened").asInt());
                assertThat(listed("owasp_category=any&resolved_from=" + days.formatted("resolved"), asAdmin()))
                        .as("resolved, " + monday).hasSize(week.path("resolved").asInt());
                assertThat(listed("owasp_category=any&reopened_from=" + days.formatted("reopened"), asAdmin()))
                        .as("reopened, " + monday).hasSize(week.path("reopened").asInt());
                assertThat(listed("owasp_category=any&open_at=" + monday.plusDays(6), asAdmin()))
                        .as("open at the end, " + monday).hasSize(week.path("open").asInt());
            }
            JsonNode week = weekly("from=2025-03-03&to=2025-03-03", asAdmin()).path("weeks").get(0);
            assertThat(week.path("opened").asInt()).as("not a vacuous agreement").isPositive();
            assertThat(week.path("reopened").asInt()).isPositive();
            assertThat(listed("first_seen_from=2025-03-03&first_seen_to=2025-03-09", asAdmin()))
                    .as("without the filter, the licence, quality, unplaced and plugin findings join in")
                    .hasSizeGreaterThan(week.path("opened").asInt());
        });
    }

    // ------------------------------------------------------------------------------ the drill-down

    @Nested
    @DisplayName("the backlog's drill-down filters")
    class DrillDown {

        @Test
        @DisplayName("open_at lists what was open at the end of that day — a since-resolved issue among them")
        void openAt() throws Exception {
            Backlog backlog = aBoundaryBacklog(repository());

            assertThat(listed("open_at=2025-03-09", asAdmin()))
                    .as("the week's Sunday: everything open at its end, placed in a category or not")
                    .containsExactlyInAnyOrder(backlog.atStart(), backlog.resolvedAtTheEnd(), backlog.code(),
                            backlog.unplaced(), backlog.plugin());
            assertThat(listed("open_at=2025-03-09&state=open&owasp_category=A06", asAdmin()))
                    .as("a state named still holds").containsExactly(backlog.atStart());
            assertThat(listed("open_at=2025-03-09&owasp_category=A06", asAdmin()))
                    .as("the figure the A06 cell showed: two")
                    .containsExactlyInAnyOrder(backlog.atStart(), backlog.resolvedAtTheEnd());
        }

        @Test
        @DisplayName("first_seen and resolved ranges list the week's flow bars, resolved or not, each day included")
        void flows() throws Exception {
            Backlog backlog = aBoundaryBacklog(repository());

            assertThat(listed("first_seen_from=2025-03-03&first_seen_to=2025-03-09&owasp_category=A06", asAdmin()))
                    .containsExactly(backlog.atStart());
            assertThat(listed("first_seen_from=2025-03-10&first_seen_to=2025-03-16", asAdmin()))
                    .as("first seen at the next Monday's midnight").containsExactly(backlog.atTheEnd());
            assertThat(listed("resolved_from=2025-03-03&resolved_to=2025-03-09", asAdmin()))
                    .as("resolved a second before the week's end, and not the one resolved at it")
                    .containsExactly(backlog.resolvedBefore());
            assertThat(listed("resolved_from=2025-03-10&resolved_to=2025-03-10", asAdmin()))
                    .containsExactly(backlog.resolvedAtTheEnd());
        }

        @Test
        @DisplayName("owasp_category places as the grid does: a vulnerability is A06 with no column, a plugin's finding nowhere")
        void category() throws Exception {
            long repo = repository();
            long vulnerability = issue(repo, FindingType.VULNERABILITY, null, EARLIER, null);
            long endOfLife = issue(repo, FindingType.EOL, null, EARLIER, null);
            long declared = issue(repo, FindingType.SAST, "A06", EARLIER, null);
            issue(repo, FindingType.PLUGIN, "A06", EARLIER, null);
            long injection = issue(repo, FindingType.SAST, "A03", EARLIER, null);

            assertThat(listed("owasp_category=A06", asAdmin()))
                    .containsExactlyInAnyOrder(vulnerability, endOfLife, declared);
            assertThat(listed("owasp_category=a03", asAdmin())).as("case aside").containsExactly(injection);
            assertThat(listed("owasp_category=A01", asAdmin())).isEmpty();
        }

        @Test
        @DisplayName("owasp_category=any lists every issue the grid places in one of the ten, by the placement itself")
        void anyCategory() throws Exception {
            long repo = repository();
            java.util.Set<Long> placed = new java.util.HashSet<>();
            for (FindingType type : FindingType.values()) {
                for (String declared : java.util.Arrays.asList(null, "A03", "A10", "A11", "")) {
                    long id = issue(repo, type, declared, EARLIER, null);
                    if (com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.placementOf(type, declared).isPresent()) {
                        placed.add(id);
                    }
                }
            }
            assertThat(placed).as("not vacuous").isNotEmpty();
            assertThat(listed("owasp_category=any", asAdmin())).containsExactlyInAnyOrderElementsOf(placed);
            assertThat(listed("owasp_category=Any", asAdmin())).as("case aside").containsExactlyInAnyOrderElementsOf(placed);
        }

        @Test
        @DisplayName("refuses a category that does not exist, a date it cannot read and a range that runs backwards")
        void refusals() throws Exception {
            assertThat(listRefused("owasp_category=A11"))
                    .isEqualTo("Unknown OWASP category \"A11\". Expected one of: A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, or any.");
            assertThat(listRefused("reopened_from=2025-03-10&reopened_to=2025-03-09"))
                    .isEqualTo("reopened_to comes before reopened_from.");
            assertThat(listRefused("reopened_from=soon")).isEqualTo("reopened_from must be an ISO date, YYYY-MM-DD: \"soon\".");
            assertThat(listRefused("open_at=yesterday")).isEqualTo("open_at must be an ISO date, YYYY-MM-DD: \"yesterday\".");
            assertThat(listRefused("open_at=+10000-01-01")).isEqualTo("open_at must be a date between 1970 and 9998.");
            assertThat(listRefused("resolved_from=2025-03-10&resolved_to=2025-03-09"))
                    .isEqualTo("resolved_to comes before resolved_from.");
        }

        @Test
        @DisplayName("stays within what the reader sees")
        void visibility() throws Exception {
            restrict();
            long mine = repository();
            long theirs = repository();
            long own = issue(mine, FindingType.VULNERABILITY, null, EARLIER, NEXT_WEEK);
            issue(theirs, FindingType.VULNERABILITY, null, EARLIER, NEXT_WEEK);
            String reader = asReader();
            grant(readerId(), "repository", mine);

            assertThat(listed("open_at=2025-03-09&owasp_category=A06", reader)).containsExactly(own);
        }
    }

    // ------------------------------------------------------------------------------ fixtures

    private record Estate(long alpha, long beta) {}

    /**
     * Two scanned repositories: alpha with an open vulnerability, one accepted as not affecting it and
     * an accepted secret; beta with an open misconfiguration, an open vulnerability, an open secret and an
     * accepted one. A07 thus reads clean on alpha and has findings on beta, each with a settled one: the
     * settled figure is summed across targets of different states.
     */
    private Estate anEstate() {
        long alpha = repository();
        long beta = repository();
        scan(alpha);
        scan(beta);
        Instant seen = Instant.now().minusSeconds(3600);
        issue(alpha, FindingType.VULNERABILITY, null, seen, null);
        triaged(issue(alpha, FindingType.VULNERABILITY, null, seen, null), TriageStatus.NOT_AFFECTED);
        triaged(issue(alpha, FindingType.SECRET, null, seen, null), TriageStatus.NOT_AFFECTED);
        issue(beta, FindingType.IAC, null, seen, null);
        issue(beta, FindingType.VULNERABILITY, null, seen, null);
        issue(beta, FindingType.SECRET, null, seen, null);
        triaged(issue(beta, FindingType.SECRET, null, seen, null), TriageStatus.NOT_AFFECTED);
        return new Estate(alpha, beta);
    }

    /**
     * A repository nothing has scanned, with an open vulnerability, an open misconfiguration and an
     * accepted one: the grid counts the open ones once a visible target beside it is scanned.
     */
    private long aNeverScannedTarget() {
        long gamma = repository();
        Instant seen = Instant.now().minusSeconds(3600);
        issue(gamma, FindingType.VULNERABILITY, null, seen, null);
        issue(gamma, FindingType.IAC, null, seen, null);
        triaged(issue(gamma, FindingType.IAC, null, seen, null), TriageStatus.NOT_AFFECTED);
        return gamma;
    }

    /**
     * @param atStart a vulnerability first seen at the week's first instant, still open
     * @param atTheEnd a secret first seen at the next Monday's midnight
     * @param resolvedAtTheEnd a vulnerability resolved at the next Monday's midnight
     * @param resolvedBefore a vulnerability resolved a second before it
     * @param code code analysis declaring A03, first seen mid-week
     * @param unplaced code analysis declaring nothing, first seen mid-week: in no category
     * @param plugin a plugin's finding carrying A03, first seen mid-week: in no category either
     */
    private record Backlog(
            long atStart, long atTheEnd, long resolvedAtTheEnd, long resolvedBefore, long code, long unplaced, long plugin) {}

    private Backlog aBoundaryBacklog(long repo) {
        Instant midWeek = Instant.parse("2025-03-05T12:00:00Z");
        return new Backlog(
                issue(repo, FindingType.VULNERABILITY, null, WEEK, null),
                issue(repo, FindingType.SECRET, null, NEXT_WEEK, null),
                issue(repo, FindingType.VULNERABILITY, null, EARLIER, NEXT_WEEK),
                issue(repo, FindingType.VULNERABILITY, null, EARLIER, NEXT_WEEK.minusSeconds(1)),
                issue(repo, FindingType.SAST, "A03", midWeek, null),
                issue(repo, FindingType.SAST, null, midWeek, null),
                issue(repo, FindingType.PLUGIN, "A03", midWeek, null));
    }

    /**
     * @param reopened a vulnerability first seen long before, resolved on the week's Wednesday and found
     *     again at the Monday two weeks on, at midnight — open today, its earlier resolution in the history
     * @param unrecorded a vulnerability first seen long before and open today, with no entry: a reopening
     *     before the history recorded them reads as an issue open throughout
     */
    private record Reopened(long reopened, long unrecorded) {}

    private Reopened aReopenedBacklog(long repo) {
        long reopened = issue(repo, FindingType.VULNERABILITY, null, EARLIER, null);
        TriageEventEntity reopening = new TriageEventEntity();
        reopening.setIssueId(reopened);
        reopening.setFromStatus(TriageStatus.FIXED.wireName());
        reopening.setToStatus(TriageStatus.UNDER_REVIEW.wireName());
        reopening.setOrigin(TriageOrigin.REOPENING.wireName());
        reopening.setPreviousResolvedAt(Instant.parse("2025-03-05T00:00:00Z"));
        reopening.setOccurredAt(Instant.parse("2025-03-17T00:00:00Z"));
        events.save(reopening);
        return new Reopened(reopened, issue(repo, FindingType.VULNERABILITY, null, EARLIER, null));
    }

    /** A reopening entry of the history for this issue, at this instant, ending a resolution a week before. */
    private TriageEventEntity reopening(long issueId, Instant at) {
        TriageEventEntity reopening = new TriageEventEntity();
        reopening.setIssueId(issueId);
        reopening.setFromStatus(TriageStatus.UNDER_REVIEW.wireName());
        reopening.setToStatus(TriageStatus.UNDER_REVIEW.wireName());
        reopening.setOrigin(TriageOrigin.REOPENING.wireName());
        reopening.setPreviousResolvedAt(at.minusSeconds(7 * 86_400));
        reopening.setOccurredAt(at);
        return events.save(reopening);
    }

    private interface Checks {
        void run() throws Exception;
    }

    /**
     * Runs {@code checks} as if V68 had been applied at {@code installedOn} — the instant Flyway's history
     * holds, which the test database sets at the start of the run, after every week these cases read. The
     * row is put back whatever happens: every later case of the run reads it.
     */
    private void recordingReopeningsSince(String installedOn, Checks checks) throws Exception {
        java.sql.Timestamp applied = jdbc.queryForObject(
                "select installed_on from flyway_schema_history where version = '68'", java.sql.Timestamp.class);
        jdbc.update("update flyway_schema_history set installed_on = ? where version = '68'",
                java.sql.Timestamp.valueOf(installedOn));
        try {
            checks.run();
        } finally {
            jdbc.update("update flyway_schema_history set installed_on = ? where version = '68'", applied);
        }
    }

    private static void assertSameAsTheGrid(JsonNode week, JsonNode grid) {
        for (JsonNode line : grid.path("lines")) {
            JsonNode recorded = category(week, line.path("id").asText());
            assertThat(recorded.path("state").asText()).as(line.path("id").asText()).isEqualTo(line.path("state").asText());
            assertThat(recorded.path("open").asLong()).as(line.path("id").asText()).isEqualTo(line.path("findings").asLong());
        }
    }

    private static List<Long> counts(JsonNode week, String category) {
        JsonNode line = category(week, category);
        return List.of(line.path("open").asLong(), line.path("opened").asLong(), line.path("resolved").asLong());
    }

    private static JsonNode category(JsonNode week, String id) {
        return StreamSupport.stream(week.path("categories").spliterator(), false)
                .filter(line -> line.path("category").asText().equals(id))
                .findFirst()
                .orElseThrow();
    }

    private static JsonNode lastWeek(JsonNode answer) {
        JsonNode weeks = answer.path("weeks");
        return weeks.get(weeks.size() - 1);
    }

    private JsonNode weekly(String query, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/owasp/coverage/weekly?" + query), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private JsonNode grid(String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/owasp/coverage"), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private String refused(String query, String token) throws Exception {
        return detailOf(mvc.perform(authenticated(get("/api/v1/owasp/coverage/weekly?" + query), token))
                .andExpect(status().isBadRequest())
                .andReturn());
    }

    private MvcResult notFound(String query, String token) throws Exception {
        return mvc.perform(authenticated(get("/api/v1/owasp/coverage/weekly?" + query), token))
                .andExpect(status().isNotFound())
                .andReturn();
    }

    private List<Long> listed(String query, String token) throws Exception {
        JsonNode page = json.readTree(mvc.perform(authenticated(get("/api/v1/issues?limit=500&" + query), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        return StreamSupport.stream(page.path("items").spliterator(), false).map(item -> item.path("id").asLong()).toList();
    }

    private String listRefused(String query) throws Exception {
        return detailOf(mvc.perform(authenticated(get("/api/v1/issues?" + query), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn());
    }

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    private long solution() throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "solution-" + System.nanoTime()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private long project(long solution, String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private void file(long project, long repository) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + repository), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void grant(long userId, List<Long> repositories) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(repositories.stream().map(id -> Map.of("kind", "repository", "id", id)).toList())))
                .andExpect(status().isOk());
    }

    private void grant(long userId, String kind, long id) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", kind, "id", id)))))
                .andExpect(status().isOk());
    }

    private long idOf(String body) throws Exception {
        return json.readTree(body).path("id").asLong();
    }

    /** The reader account's identifier, read back through the administration listing. */
    private long readerId() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn().getResponse().getContentAsString();
        for (JsonNode node : json.readTree(body).path("users")) {
            if (node.path("username").asText("").startsWith("reader-")) {
                return node.path("id").asLong();
            }
        }
        throw new IllegalStateException("no reader account in the listing");
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/owasp-weekly-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now().minusSeconds(7200));
        scans.save(scan);
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

    private void triaged(long issueId, TriageStatus status) {
        IssueEntity issue = issues.findById(issueId).orElseThrow();
        issue.setTriageStatus(status.wireName());
        issues.save(issue);
    }
}

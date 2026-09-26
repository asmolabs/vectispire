package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The stored resolution time, written once and read as an average.
 *
 * <p><b>Why the column exists.</b> Mean time to resolution is the gap between two instants, and
 * MySQL, PostgreSQL and SQLite each express that differently — so the dashboard used to fetch
 * every closed issue in the estate and average them in Java. Storing the gap when the issue
 * closes turns the whole thing into {@code avg} of a number, which is one statement on all three
 * engines. The dialects are named once, in the migration, where they are named anyway.
 *
 * <p>That trade only holds if the column is right, and it can be wrong in two independent ways
 * that no compiler sees: the write path can drift from {@code resolvedAt}, and the migration's
 * backfill can compute something else entirely for the rows that already exist. Both are checked
 * here.
 *
 * <p><b>The backfill is executed from the shipped file, not retyped.</b> A test carrying its own
 * copy of the statement proves that the copy works. Reading {@code V24} means editing the
 * migration wrongly fails here — which is the only place it could fail before production, since
 * a backfill runs exactly once and against data no test fixture contains.
 */
@DisplayName("the stored resolution time")
class ResolutionSecondsTest extends VectispireContextTest {

    private static final Instant SEEN = Instant.parse("2026-01-10T08:00:00Z");

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("is written by the entity together with the resolution, never apart from it")
    void is_written_together_with_the_resolution() {
        IssueEntity issue = new IssueEntity();
        issue.setFirstSeenAt(SEEN);

        issue.resolveAt(SEEN.plus(Duration.ofDays(3)));
        assertThat(issue.getResolutionSeconds()).isEqualTo(3 * 86_400L);

        issue.reopen();
        assertThat(issue.getResolvedAt()).isNull();
        assertThat(issue.getResolutionSeconds())
                .as("a reopened issue has no duration; leaving the old one would keep averaging it")
                .isNull();
    }

    @Test
    @DisplayName("the state moves with the instant: resolving closes the issue, reopening opens it")
    void theStateTravelsWithTheResolution() {
        // State, instant and duration were three public setters; a path setting one of them left
        // an issue "resolved" with no date, or dated and still open, and the MTTR drifted. Two of
        // this suite's own fixtures had exactly that shape.
        IssueEntity issue = new IssueEntity();
        issue.setFirstSeenAt(SEEN);
        issue.setState("open");

        issue.resolveAt(SEEN.plus(Duration.ofDays(1)));
        assertThat(issue.getState()).isEqualTo("resolved");

        issue.reopen();
        assertThat(issue.getState()).isEqualTo("open");
        assertThat(issue.getResolvedAt()).isNull();
    }

    @Test
    @DisplayName("stays null for the three cases the average has always skipped")
    void stays_null_where_there_is_nothing_to_measure() {
        IssueEntity closedInTheSameInstant = new IssueEntity();
        closedInTheSameInstant.setFirstSeenAt(SEEN);
        closedInTheSameInstant.resolveAt(SEEN);
        assertThat(closedInTheSameInstant.getResolutionSeconds()).isNull();

        IssueEntity neverSeen = new IssueEntity();
        neverSeen.resolveAt(SEEN);
        assertThat(neverSeen.getResolutionSeconds()).isNull();

        IssueEntity resolvedBeforeItWasSeen = new IssueEntity();
        resolvedBeforeItWasSeen.setFirstSeenAt(SEEN);
        resolvedBeforeItWasSeen.resolveAt(SEEN.minusSeconds(60));
        assertThat(resolvedBeforeItWasSeen.getResolutionSeconds())
                .as("nonsense data must not become a negative contribution to the mean")
                .isNull();
    }

    @Test
    @DisplayName("is computed by the migration exactly as the entity computes it")
    void the_backfill_agrees_with_the_write_path() {
        seed(1, SEEN, SEEN.plus(Duration.ofDays(3)));
        seed(2, SEEN, SEEN);
        seed(4, SEEN, null);
        seed(5, SEEN, SEEN.minusSeconds(60));

        // No row for "never seen": `first_seen_at` is NOT NULL in the schema, so that case is
        // reachable in memory and not in the table. The backfill's guard on it is belt and
        // braces, and this line is why it looks unreachable rather than wrong.

        // Rows arrive with the column empty, as they would after `alter table`.
        jdbc.update("update t_issue set resolution_seconds = null where id between 1 and 5");
        jdbc.execute(backfillStatementFrom("db/migration/sqlite/V24__issue_resolution_seconds.sql"));

        assertThat(secondsOf(1))
                .as("three days, the one row with something to measure")
                .isEqualTo(3 * 86_400L);
        assertThat(secondsOf(2)).as("closed in its own instant").isNull();
        assertThat(secondsOf(4)).as("still open").isNull();
        assertThat(secondsOf(5)).as("resolved before it was seen").isNull();

        // The write path, on the same input, has to agree — that is the whole claim.
        IssueEntity same = new IssueEntity();
        same.setFirstSeenAt(SEEN);
        same.resolveAt(SEEN.plus(Duration.ofDays(3)));
        assertThat(secondsOf(1)).isEqualTo(same.getResolutionSeconds());
    }

    private Long secondsOf(long id) {
        return jdbc.queryForObject("select resolution_seconds from t_issue where id = ?", Long.class, id);
    }

    private void seed(long id, Instant firstSeen, Instant resolvedAt) {
        jdbc.update(
                """
                insert into t_issue (id, repo_id, fingerprint, type, identifier, severity, state,
                                     is_kev, reachability, first_seen_at, last_seen_at, resolved_at,
                                     times_seen, resolution_seconds)
                values (?, null, ?, 'VULNERABILITY', 'CVE-0000-0000', 'HIGH', ?, 0, 'UNKNOWN', ?, ?, ?, 1, ?)
                """,
                id,
                "fingerprint-" + id,
                resolvedAt == null ? "OPEN" : "RESOLVED",
                firstSeen.toEpochMilli(),
                SEEN.toEpochMilli(),
                resolvedAt == null ? null : resolvedAt.toEpochMilli(),
                resolvedAt != null && resolvedAt.isAfter(firstSeen)
                        ? Duration.between(firstSeen, resolvedAt).toSeconds()
                        : null);
    }

    /** The {@code update} from the shipped migration, comments and DDL stripped. */
    private static String backfillStatementFrom(String resource) {
        try (InputStream stream = ResolutionSecondsTest.class.getClassLoader().getResourceAsStream(resource)) {
            if (stream == null) {
                throw new AssertionError("migration not on the classpath: " + resource);
            }
            String sql = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            String statements = Arrays.stream(sql.split("\n"))
                    .filter(line -> !line.stripLeading().startsWith("--"))
                    .collect(Collectors.joining("\n"));

            return Arrays.stream(statements.split(";"))
                    .map(String::strip)
                    .filter(statement -> statement.toLowerCase().startsWith("update"))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("no update statement in " + resource));
        } catch (IOException unreadable) {
            throw new AssertionError(unreadable);
        }
    }
}

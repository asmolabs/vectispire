package com.asmolabs.zanshin.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import liquibase.Liquibase;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The changelog, executed rather than read.
 *
 * <p>A YAML file that parses is not a schema. This runs the whole thing against SQLite — the one
 * engine that needs no daemon — so a typo in a type, a column named twice, or a foreign key
 * pointing at a table declared later fails here, in a second, instead of in the integration
 * campaign minutes later or in a deployment.
 *
 * <p>It proves the changelog is <em>coherent</em>, not that it is <em>portable</em>. Portability
 * is what {@code SchemaParityIntegrationTest} is for, on all four engines, because the places
 * the engines disagree are exactly the places SQLite is most forgiving about.
 */
@DisplayName("the schema changelog")
class ChangelogTest {

    private static final String MASTER = "db/changelog/db.changelog-master.yaml";

    @TempDir
    Path scratch;

    private static void apply(Path database) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
            var target = DatabaseFactory.getInstance()
                    .findCorrectDatabaseImplementation(new JdbcConnection(connection));
            // `Liquibase.close()` closes the connection it was handed, so nothing may be read
            // through it afterwards. Reopening is one line; sharing the handle is a test that
            // fails on a closed connection and looks like a schema problem.
            try (Liquibase liquibase = new Liquibase(MASTER, new ClassLoaderResourceAccessor(), target)) {
                liquibase.update("");
            }
        }
    }

    private List<String> applyChangelog() throws Exception {
        Path database = scratch.resolve("zanshin.db");
        Files.createDirectories(database.getParent());
        apply(database);

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
                ResultSet rows = connection.getMetaData().getTables(null, null, "t\\_%", null)) {
            List<String> tables = new ArrayList<>();
            while (rows.next()) {
                tables.add(rows.getString("TABLE_NAME"));
            }
            return tables;
        }
    }

    @Test
    @DisplayName("applies cleanly and creates every table")
    void createsEveryTable() throws Exception {
        assertThat(applyChangelog())
                .containsExactlyInAnyOrder(
                        "t_api_key", "t_agent", "t_ssh_key", "t_container", "t_repository", "t_scan",
                        "t_ai_review_result", "t_audit_log", "t_issue", "t_finding", "t_gate_policy",
                        "t_leader_lease", "t_login_attempt", "t_outbox_message", "t_processed_message",
                        "t_user", "t_user_target", "t_session", "t_setting", "t_semgrep_rule_set",
                        "t_issue_triage_event", "t_component");
    }

    @Test
    @DisplayName("the foreign keys really exist on SQLite, which is why they are inline")
    void foreignKeysArePresent() throws Exception {
        // The point of declaring them inline. Written as `addForeignKeyConstraint` the
        // changelog applies without complaint on SQLite and creates no constraint at all —
        // referential integrity on three engines out of four, and nothing saying so.
        Path database = scratch.resolve("fk.db");
        apply(database);

        List<String> references = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
            // Every table with a foreign key, listed. A table added here and forgotten in the
            // list below would make this test pass while checking one table fewer — which is how
            // a suite comes to prove less than its name says.
            for (String table : List.of(
                    "t_scan", "t_issue", "t_finding", "t_session", "t_agent", "t_repository",
                    "t_ai_review_result", "t_user_target", "t_issue_triage_event", "t_component")) {
                try (ResultSet rows = connection.getMetaData().getImportedKeys(null, null, table)) {
                    while (rows.next()) {
                        references.add(table + "." + rows.getString("FKCOLUMN_NAME")
                                + " -> " + rows.getString("PKTABLE_NAME"));
                    }
                }
            }
        }

        assertThat(references)
                .contains(
                        "t_scan.repo_id -> t_repository",
                        "t_scan.container_id -> t_container",
                        "t_issue.first_seen_scan_id -> t_scan",
                        "t_finding.scan_id -> t_scan",
                        "t_finding.issue_id -> t_issue",
                        "t_session.user_id -> t_user",
                        "t_agent.api_key_id -> t_api_key",
                        "t_repository.ssh_key_id -> t_ssh_key",
                        "t_user_target.user_id -> t_user",
                        "t_issue_triage_event.issue_id -> t_issue",
                        "t_issue_triage_event.scan_id -> t_scan",
                        "t_component.scan_id -> t_scan")
                .hasSize(16);
    }

    @Test
    @DisplayName("is idempotent, so a second startup changes nothing")
    void isIdempotent() throws Exception {
        // Every instance runs the changelog on boot. If a second application were not a no-op,
        // the second pod to start would fail — and the failure would look like a race rather
        // than like a changelog that cannot be replayed.
        Path database = scratch.resolve("twice.db");

        apply(database);
        apply(database);
    }
}

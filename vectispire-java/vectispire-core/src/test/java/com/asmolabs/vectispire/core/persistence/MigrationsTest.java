package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The schema migrations, executed rather than read.
 *
 * <p>A SQL file that parses is not a schema. This runs the whole thing against SQLite — the one
 * engine that needs no daemon — so a typo in a type, a column named twice, or a foreign key
 * pointing at a table declared later fails here, in a second, instead of in the integration
 * campaign minutes later or in a deployment.
 *
 * <p>It proves the migrations are <em>coherent</em>, not that they are <em>portable</em>. Portability
 * is what {@code SchemaParityIntegrationTest} is for, on both deployable engines and the
 * fixture, because the places the engines disagree are exactly the places SQLite is most
 * forgiving about.
 */
@DisplayName("the schema migrations (Flyway)")
class MigrationsTest {

    @TempDir
    Path scratch;

    private static void apply(Path database) {
        // The locations and the placeholders the application uses on this engine, from the one
        // place that spells them: a hand-written `db/migration/sqlite` here would apply V1 to V39
        // and silently skip every common migration from V40 on.
        Flyway flyway = Flyway.configure()
                .dataSource("jdbc:sqlite:" + database, "", "")
                .locations(MigrationDialect.SQLITE.locations().toArray(String[]::new))
                .placeholders(MigrationDialect.SQLITE.placeholders())
                .load();
        flyway.migrate();
    }

    private List<String> applyMigrations() throws Exception {
        Path database = scratch.resolve("vectispire.db");
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
        assertThat(applyMigrations())
                .containsExactlyInAnyOrder(
                        "t_api_key", "t_agent", "t_ssh_key", "t_container", "t_repository", "t_scan",
                        "t_ai_review_result", "t_audit_log", "t_issue", "t_finding", "t_gate_policy",
                        "t_leader_lease", "t_login_attempt", "t_outbox_message", "t_processed_message",
                        "t_user", "t_user_target", "t_session", "t_setting", "t_semgrep_rule_set",
                        "t_issue_triage_event", "t_component", "t_team", "t_team_member", "t_team_target",
                        "t_team_webhook", "t_issue_ticket", "t_siem_config", "t_threat_intel_feed", "t_threat_intel_sync", "t_license_policy",
                        "t_api_endpoint", "t_api_contract", "t_mfa_challenge", "t_gate_verdict",
                        "t_control_declaration", "t_compliance_snapshot", "t_webhook_delivery", "t_git_token",
                        "t_solution", "t_project");
    }

    @Test
    @DisplayName("the foreign keys really exist on SQLite, which is why they are inline")
    void foreignKeysArePresent() throws Exception {
        // The point of declaring them inline. SQLite has no `alter table … add constraint`,
        // so a key that is not in the `create table` never exists on the fixture the HTTP
        // suite runs on, while the deployable engines have it. Enforcement is a separate
        // matter — the per-connection pragma, which `ForeignKeyEnforcementTest` guards.
        Path database = scratch.resolve("fk.db");
        apply(database);

        List<String> references = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
            // Every table with a foreign key, listed. A table added here and forgotten in the
            // list below would make this test pass while checking one table fewer — which is how
            // a suite comes to prove less than its name says.
            for (String table : List.of(
                    "t_scan", "t_issue", "t_finding", "t_session", "t_agent", "t_repository",
                    "t_ai_review_result", "t_user_target", "t_issue_triage_event", "t_component",
                    "t_team_member", "t_team_target", "t_team_webhook", "t_issue_ticket",
                    "t_mfa_challenge", "t_gate_verdict", "t_project")) {
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
                        "t_repository.https_token_id -> t_git_token",
                        "t_user_target.user_id -> t_user",
                        "t_issue_triage_event.issue_id -> t_issue",
                        "t_issue_triage_event.scan_id -> t_scan",
                        "t_component.scan_id -> t_scan",
                        "t_team_member.team_id -> t_team",
                        "t_team_member.user_id -> t_user",
                        "t_team_target.team_id -> t_team",
                        "t_team_webhook.team_id -> t_team",
                        "t_issue_ticket.issue_id -> t_issue",
                        "t_mfa_challenge.user_id -> t_user",
                        "t_gate_verdict.repo_id -> t_repository",
                        "t_gate_verdict.container_id -> t_container",
                        "t_repository.project_id -> t_project",
                        "t_project.solution_id -> t_solution")
                .hasSize(27);
    }

    @Test
    @DisplayName("is idempotent, so a second startup changes nothing")
    void isIdempotent() throws Exception {
        // Every instance runs the migrations on boot. If a second application were not a no-op,
        // the second pod to start would fail — and the failure would look like a race rather
        // than like a migration that cannot be replayed.
        Path database = scratch.resolve("twice.db");

        apply(database);
        apply(database);
    }
}

package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.TestDatabase;
import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The schema migrations, executed rather than read.
 *
 * <p>A SQL file that parses is not a schema. This runs the whole set against MySQL, the engine the
 * suite runs on (decision 0034), in a database of its own, so a typo in a type, a column named twice,
 * or a foreign key pointing at a table declared later fails in the build instead of in the campaign
 * or a deployment.
 *
 * <p>It proves the migrations are <em>coherent</em> on one engine, not that they are
 * <em>portable</em>: PostgreSQL is {@code SchemaParityIntegrationTest}'s, in the campaign.
 */
@DisplayName("the schema migrations (Flyway)")
class MigrationsTest {

    private static void apply(TestDatabase.Scratch database) {
        // The locations and the placeholders the application uses on this engine, from the one
        // place that spells them: a hand-written `db/migration/mysql` here would apply V1 to V39
        // and silently skip every common migration from V40 on.
        Flyway flyway = Flyway.configure()
                .dataSource(database.url(), database.user(), database.password())
                .locations(MigrationDialect.MYSQL.locations().toArray(String[]::new))
                .placeholders(MigrationDialect.MYSQL.placeholders())
                .load();
        flyway.migrate();
    }

    private static Connection connect(TestDatabase.Scratch database) throws Exception {
        return DriverManager.getConnection(database.url(), database.user(), database.password());
    }

    private List<String> applyMigrations() throws Exception {
        try (TestDatabase.Scratch database = TestDatabase.scratch()) {
            apply(database);
            try (Connection connection = connect(database);
                    ResultSet rows = connection.getMetaData().getTables(connection.getCatalog(), null, "t\\_%", null)) {
                List<String> tables = new ArrayList<>();
                while (rows.next()) {
                    tables.add(rows.getString("TABLE_NAME"));
                }
                return tables;
            }
        }
    }

    @Test
    @DisplayName("applies cleanly and creates every table")
    void createsEveryTable() throws Exception {
        assertThat(applyMigrations())
                .containsExactlyInAnyOrder(
                        "t_api_key", "t_agent", "t_audit_chain_head", "t_ssh_key", "t_container", "t_repository", "t_scan",
                        "t_ai_review_result", "t_audit_log", "t_issue", "t_finding", "t_gate_policy",
                        "t_leader_lease", "t_login_attempt", "t_outbox_message", "t_processed_message",
                        "t_user", "t_user_target", "t_session", "t_setting", "t_semgrep_rule_set",
                        "t_issue_triage_event", "t_component", "t_team", "t_team_member", "t_team_target",
                        "t_team_webhook", "t_issue_ticket", "t_siem_config", "t_threat_intel_feed", "t_threat_intel_sync", "t_license_policy",
                        "t_api_endpoint", "t_api_contract", "t_mfa_challenge", "t_gate_verdict",
                        "t_control_declaration", "t_compliance_snapshot", "t_webhook_delivery", "t_git_token",
                        "t_solution", "t_project",
                        "t_plugin", "t_plugin_manifest", "t_plugin_activation", "t_sarif_source", "t_sarif_import",
                        "t_coverage_import", "t_test_report_import", "t_test_suite_result",
                        "t_rate_window", "t_epss_score", "t_one_shot_job",
                        "t_checklist_template", "t_checklist_template_version", "t_checklist_item",
                        "t_checklist", "t_checklist_answer", "t_checklist_evidence", "t_checklist_file",
                        "t_checklist_measurement", "t_checklist_document");
    }

    @Test
    @DisplayName("the foreign keys really exist on MySQL, inline or not, and each exactly once")
    void foreignKeysArePresent() throws Exception {
        // MySQL 8 parses a column-level `references` and drops it without a word, so a key declared
        // only inline exists on PostgreSQL and not there: each must be a named `add constraint`
        // (V19, V37, V65 and their successors). MySQL 9 honours the inline form, so on the image pinned
        // here V1's inline keys existed twice — InnoDB's `t_scan_ibfk_1` beside V19's `fk_scan_repo`
        // — until V65 dropped the twins; and `t_mfa_challenge.user_id`, inline in V23, was a key on
        // MySQL 9 only, which this test could not see while it counted distinct references. Listed,
        // not collected in a set: a key that exists twice fails here. Enforcement is
        // `ForeignKeyEnforcementTest`'s.
        List<String> references = new ArrayList<>();
        try (TestDatabase.Scratch database = TestDatabase.scratch()) {
            apply(database);
            try (Connection connection = connect(database)) {
                // Every table with a foreign key, listed. A table added here and forgotten in the
                // list below would make this test pass while checking one table fewer — which is how
                // a suite comes to prove less than its name says.
                for (String table : List.of(
                        "t_scan", "t_issue", "t_finding", "t_session", "t_agent", "t_repository",
                        "t_ai_review_result", "t_user_target", "t_issue_triage_event", "t_component",
                        "t_team_member", "t_team_target", "t_team_webhook", "t_issue_ticket",
                        "t_mfa_challenge", "t_gate_verdict", "t_project")) {
                    try (ResultSet rows = connection.getMetaData().getImportedKeys(connection.getCatalog(), null, table)) {
                        while (rows.next()) {
                            references.add(table + "." + rows.getString("FKCOLUMN_NAME")
                                    + " -> " + rows.getString("PKTABLE_NAME"));
                        }
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
                .hasSize(27)
                .doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("is idempotent, so a second startup changes nothing")
    void isIdempotent() throws Exception {
        // Every instance runs the migrations on boot. If a second application were not a no-op,
        // the second pod to start would fail — and the failure would look like a race rather
        // than like a migration that cannot be replayed.
        try (TestDatabase.Scratch database = TestDatabase.scratch()) {
            apply(database);
            apply(database);
        }
    }
}

package com.asmolabs.vectispire.core;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The whole application, on a real database, in the ordinary unit suite.
 *
 * <p><b>MySQL, the engine deployments run</b> (decision 0034), in a container or on the server CI
 * gives the job — see {@link TestDatabase}. It replaced a SQLite file, which needed no daemon and
 * validated no schema; here Hibernate validates every entity against the migrated tables at each
 * context start, as it does in production.
 *
 * <p><b>The tables are emptied between tests, not wrapped in a rolled-back transaction.</b> The
 * usual {@code @Transactional} test would join its transaction to the code under test, which
 * changes the very thing several of these services depend on: the outbox enqueues with {@code
 * MANDATORY}, the audit log writes with {@code REQUIRES_NEW}, and the scan queue deliberately
 * runs outside any transaction. A suite that rewrote those boundaries would be green about
 * behaviour production does not have — which is the one thing worse than no suite.
 */
@SpringBootTest(classes = VectispireApplication.class)
@ActiveProfiles("apitest")
public abstract class VectispireContextTest {

    /**
     * This JVM's database, emptied before the context starts on it.
     *
     * <p>Shared by every context rather than one each, since migrating MySQL once per context would add
     * a minute ({@link TestDatabase}); the emptying is what keeps a context's start-up — its repairs,
     * its resumed purges — from finding what the previous class's last test left.
     */
    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.emptyBeforeAContextStarts(TABLES_CHILDREN_FIRST);
        TestDatabase.register(registry);
    }

    /**
     * Every table, children before parents.
     *
     * <p>Listed rather than discovered: a generated order would be right until the day a new
     * foreign key changes it, and the failure — a delete refused mid-cleanup — reads as a broken
     * test rather than as a missing entry here. A table missing from the list is found by {@link
     * TableEmptyingTest}, which reads the schema: listed, emptied by a cascade from a listed one, or
     * kept there with its reason.
     */
    static final List<String> TABLES_CHILDREN_FIRST = List.of(
            // No foreign key in or out (a common migration, decision 0027), so first or anywhere; left
            // out, a plugin registered by one test would conflict with the next test's registration.
            // No foreign key either (V51, common). Left out, a template imported by one test would hold
            // its slug's next version number, and its draft, in the next test.
            // No foreign key either (V52, common). Left out, a project's checklist would hold the next
            // test's open slot, and its revision numbers. The measurements (V54, common) likewise: left
            // out, a sign-off would compare with another test's submission. The documents (V55, common)
            // likewise: left out, a revision's number would find another test's signed package.
            "t_checklist_document",
            "t_checklist_measurement",
            "t_checklist_file",
            "t_checklist_evidence",
            "t_checklist_answer",
            "t_checklist",
            "t_checklist_item",
            "t_checklist_template_version",
            "t_checklist_template",
            "t_sarif_import",
            "t_coverage_package",
            "t_coverage_import",
            "t_test_suite_result",
            "t_test_report_import",
            "t_sarif_source",
            "t_plugin_activation",
            "t_plugin_manifest",
            "t_plugin",
            "t_ai_review_result",
            // No foreign key either. Left out, the catalogue a test synchronised was the next test's,
            // and a status test read "SYNCED" before anything had been synchronised.
            "t_threat_intel_feed",
            "t_threat_intel_sync",
            // The same for the EPSS file: a generation a test applied would score the next test's CVE.
            "t_epss_score",
            "t_finding",
            "t_issue",
            "t_scan",
            "t_gate_policy",
            // Each verdict names a repository or a container, and goes with it through a cascade — but both
            // columns are nullable, so the cascade proves nothing about a row naming neither: named here.
            "t_gate_verdict",
            // No foreign key to cascade from, unlike t_gate_verdict which a repository takes with
            // it: a declaration belongs to the management system, not to a target. Left out, it
            // would survive into the next test and the failure would read as a duplicate write.
            "t_control_declaration",
            "t_compliance_snapshot",
            // No foreign key either (V67, common). Left out, one test's capture would make the next test's
            // week "not due", and its rows would be counted in the next test's week.
            "t_owasp_weekly_coverage",
            // A singleton row: left behind, it made the next SIEM test start "enabled".
            "t_siem_config",
            "t_processed_message",
            "t_outbox_message",
            // Named rather than left to a cascade. Left out, a team outlived its test: the SCIM
            // group tests found the previous test's groups in their listing, and its names taken.
            "t_team_webhook",
            "t_team_target",
            "t_team_member",
            "t_team",
            "t_audit_log",
            "t_login_attempt",
            // The webhook's shared ceiling: left behind, one test's deliveries count against the
            // next's, all of them from the one address MockMvc gives.
            "t_rate_window",
            // The tracker deliveries already acted on (V35). Left out, a delivery one test sent would be
            // refused as a replay in the next test that sends the same body.
            "t_webhook_delivery",
            "t_session",
            "t_api_key",
            "t_agent",
            "t_repository",
            // After t_repository, which names its project, and before t_solution, which the
            // project names: the foreign keys are enforced.
            "t_project",
            "t_solution",
            "t_container",
            "t_ssh_key",
            // After t_repository, which may name one for its HTTPS clone. Left out, a token outlived its
            // test and the next one counted rows instead of asserting none.
            "t_git_token",
            "t_semgrep_rule_set",
            "t_leader_lease",
            "t_one_shot_job",
            "t_setting",
            // A singleton row the migration seeds (V13); absent, the service reads the default policy, the
            // one seeded. Left out, a case refusing unknown licences refused them in every class run after
            // it, and the tallies' suite reset it by hand around each case.
            "t_license_policy",
            "t_user");

    @BeforeEach
    void emptyTheDatabase() {
        TestDatabase.empty(TABLES_CHILDREN_FIRST);
    }
}

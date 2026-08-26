package com.asmolabs.vectispire.core;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The whole application, on a real database, in the ordinary unit suite.
 *
 * <p><b>SQLite, so it runs on every build.</b> It needs no daemon, which is the difference
 * between a suite that runs and a suite somebody remembers to launch. What the engines
 * disagree about is the database campaign's business; what is under test here is behaviour they
 * all share — the queries, the transaction boundaries, and the wiring.
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
     * A database file nobody has touched, one per JVM.
     *
     * <p>A fresh file rather than a cleaning step, so there is no teardown that can half-fail
     * and leave the next class running against a schema nobody can describe.
     *
     * <p>Not {@code :memory:} either — Flyway and Hibernate open separate connections, and each
     * would get its own empty database: the schema would be built in one and validated against
     * another, and the failure reads as a missing table.
     */
    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        Path file = Path.of(System.getProperty("java.io.tmpdir"), "vectispire-apitest-" + UUID.randomUUID() + ".db");
        file.toFile().deleteOnExit();
        registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + file);
    }

    /**
     * Every table, children before parents.
     *
     * <p>Listed rather than discovered: a generated order would be right until the day a new
     * foreign key changes it, and the failure — a delete refused mid-cleanup — reads as a broken
     * test rather than as a missing entry here.
     */
    private static final List<String> TABLES_CHILDREN_FIRST = List.of(
            "t_ai_review_result",
            "t_finding",
            "t_issue",
            "t_scan",
            "t_gate_policy",
            "t_processed_message",
            "t_outbox_message",
            "t_audit_log",
            "t_login_attempt",
            "t_session",
            "t_api_key",
            "t_agent",
            "t_repository",
            "t_container",
            "t_ssh_key",
            "t_semgrep_rule_set",
            "t_leader_lease",
            "t_setting",
            "t_user");

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void emptyTheDatabase() {
        TABLES_CHILDREN_FIRST.forEach(table -> jdbc.execute("delete from " + table));
    }
}

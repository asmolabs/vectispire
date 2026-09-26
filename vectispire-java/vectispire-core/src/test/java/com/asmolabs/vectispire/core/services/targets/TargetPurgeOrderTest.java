package com.asmolabs.vectispire.core.services.targets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.targets.TargetDeleted;
import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.VectispireContextTest;
import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The purge of a deleted target runs children before parents, phase by phase.
 *
 * <p><b>Why the order is checked apart from the outcome.</b> Every foreign key into these tables
 * cascades or sets null, and this fixture issues the pragma that makes SQLite honour them: a purge
 * that deleted parents first would still end with nothing left, here and on both deployable engines —
 * until the day a key becomes {@code restrict}, or the pragma goes. So probes stand between the
 * phases and look: before the issues go, nothing may still hang off them and they must still be
 * there; before the scans go, likewise. A listener given the wrong phase is caught by the probe it
 * crosses, not by a constraint that today never fires.
 *
 * <p>Kept out of {@code TargetDeletionTest}'s context on purpose: to look, a probe flushes the
 * persistence context, and that flush is what hid a real defect of the purge — see there.
 */
@Import(TargetPurgeOrderTest.Probes.class)
@DisplayName("the purge of a deleted target")
class TargetPurgeOrderTest extends VectispireContextTest {

    @Autowired
    private TargetDeletionService deletion;

    @Autowired
    private BeanFactory beans;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private PhaseProbe probe;

    private TargetRowsFixture fixture;

    @BeforeEach
    void fixture() {
        fixture = new TargetRowsFixture(beans, jdbc);
        probe.reset();
    }

    @Test
    @DisplayName("takes what hangs off the issues before the issues, and what hangs off the scans before the scans")
    void childrenFirst() {
        ScanTarget doomed = fixture.repository("doomed");
        fixture.populate(doomed);

        deletion.deleteRepository(((ScanTarget.Repository) doomed).id());

        assertThat(probe.crossed()).as("both probes ran, each with something still to watch")
                .containsExactly("before issues", "before scans");
        assertThat(probe.violations()).isEmpty();
    }

    /**
     * Records rather than throws, so a violation reads as a named assertion instead of an exception
     * surfacing through the event multicaster and rolling the deletion back.
     */
    static class PhaseProbe {

        private final JdbcTemplate jdbc;
        private final EntityManager entities;
        private final List<String> crossed = new ArrayList<>();
        private final List<String> violations = new ArrayList<>();

        PhaseProbe(JdbcTemplate jdbc, EntityManager entities) {
            this.jdbc = jdbc;
            this.entities = entities;
        }

        void reset() {
            crossed.clear();
            violations.clear();
        }

        List<String> crossed() {
            return crossed;
        }

        List<String> violations() {
            return violations;
        }

        @EventListener
        @Order(TargetPurge.Phase.ISSUES - 1)
        public void beforeIssues(TargetDeleted deleted) {
            // Deletes derived by Spring Data wait in the persistence context until a flush; counting
            // with SQL before flushing would read rows the purge has in fact already taken.
            entities.flush();
            String issues = select("t_issue", deleted);
            if (count("t_issue where id in (" + issues + ")") == 0) {
                // Nothing to watch: either the fixture wrote no issue, or a phase that runs before
                // this one took them — which `crossed` then reports by the probe's absence.
                return;
            }
            crossed.add("before issues");
            expect("no triage event outlives the issue-children phase",
                    count("t_issue_triage_event where issue_id in (" + issues + ")") == 0);
            expect("no ticket link outlives the issue-children phase",
                    count("t_issue_ticket where issue_id in (" + issues + ")") == 0);
            expect("no finding of an issue outlives the findings phase",
                    count("t_finding where issue_id in (" + issues + ")") == 0);
            expect("the grants went with the references phase",
                    count("t_user_target where target_kind = '" + deleted.kind() + "' and target_id = " + deleted.id())
                            == 0);
        }

        @EventListener
        @Order(TargetPurge.Phase.SCANS - 1)
        public void beforeScans(TargetDeleted deleted) {
            entities.flush();
            String scans = select("t_scan", deleted);
            if (count("t_scan where id in (" + scans + ")") == 0) {
                return;
            }
            crossed.add("before scans");
            expect("no issue outlives the issues phase",
                    count("t_issue where id in (" + select("t_issue", deleted) + ")") == 0);
            expect("no component outlives the scan-children phase",
                    count("t_component where scan_id in (" + scans + ")") == 0);
            expect("no AI review outlives the scan-children phase",
                    count("t_ai_review_result where scan_id in (" + scans + ")") == 0);
            expect("no finding of a scan outlives the findings phase",
                    count("t_finding where scan_id in (" + scans + ")") == 0);
        }

        private static String select(String table, TargetDeleted deleted) {
            return "select id from " + table + " where "
                    + (deleted.target() instanceof ScanTarget.Repository ? "repo_id" : "container_id")
                    + " = " + deleted.id();
        }

        private void expect(String what, boolean holds) {
            if (!holds) {
                violations.add(what);
            }
        }

        private int count(String fromWhere) {
            Integer count = jdbc.queryForObject("select count(*) from " + fromWhere, Integer.class);
            return count == null ? 0 : count;
        }
    }

    @TestConfiguration
    static class Probes {

        @Bean
        PhaseProbe phaseProbe(JdbcTemplate jdbc, EntityManager entities) {
            return new PhaseProbe(jdbc, entities);
        }
    }
}

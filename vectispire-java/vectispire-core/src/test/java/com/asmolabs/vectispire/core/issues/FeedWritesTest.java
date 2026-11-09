package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What the threat-intel feeds write onto the backlog, and only that.
 *
 * <p>The KEV re-evaluation read the open issues at the start of its transaction and wrote them back
 * whole at its end; the EPSS refresh, running meanwhile in transactions of its own, had its scores put
 * back to what the KEV transaction had read. The interleaving is forced here inside one transaction:
 * a page is read, a score changes underneath it — as a committed EPSS page does — and the flag is
 * written.
 */
@DisplayName("the feeds' writes onto the backlog")
class FeedWritesTest extends VectispireContextTest {

    @Autowired
    private IssueCatalog catalog;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("a KEV flag does not put back the EPSS score its transaction read before")
    void theFlagAlone() {
        long id = issue(0.1).getId();

        transactions.executeWithoutResult(status -> {
            assertThat(catalog.openIdentifiedAfter(0, List.of("closed", "resolved"), 500, IssueRows.KevCandidate.class))
                    .isNotEmpty();
            jdbc.update("update t_issue set epss_score = 0.9 where id = ?", id);
            catalog.recordExploitation(List.of(new IssueCatalog.Exploitation(id, true)));
        });

        IssueEntity stored = issues.findById(id).orElseThrow();
        assertThat(stored.isKev()).isTrue();
        assertThat(stored.getEpssScore()).isEqualTo(0.9);
    }

    @Test
    @DisplayName("an EPSS score does not put back the KEV flag, and one statement serves the issues of one score")
    void theScoreAlone() {
        long first = issue(0.1).getId();
        long second = issue(0.2).getId();

        transactions.executeWithoutResult(status -> {
            assertThat(catalog.openIdentifiedAfter(0, List.of("closed", "resolved"), 500, IssueRows.EpssCandidate.class))
                    .hasSize(2);
            jdbc.update("update t_issue set is_kev = ? where id = ?", true, first);
            assertThat(catalog.recordEpss(Map.of(first, 0.7, second, 0.7))).isEqualTo(2);
        });

        assertThat(issues.findById(first).orElseThrow().isKev()).isTrue();
        assertThat(issues.findById(first).orElseThrow().getEpssScore()).isEqualTo(0.7);
        assertThat(issues.findById(second).orElseThrow().getEpssScore()).isEqualTo(0.7);
    }

    private IssueEntity issue(double epss) {
        IssueEntity issue = new IssueEntity();
        issue.setType("vulnerability");
        issue.setIdentifier("CVE-2026-" + System.nanoTime() % 100_000);
        issue.setFingerprint("fp-feed-" + System.nanoTime());
        issue.setPackageName("openssl");
        issue.setSource("grype");
        issue.setSeverity("high");
        issue.setState("open");
        issue.setEpssScore(epss);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTriageStatus("untriaged");
        return issues.save(issue);
    }
}

package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A ticket attached by a bulk statement raises the issue's revision (V89), so a triage that read the
 * row before it is refused instead of saving the reference away.
 *
 * <p>The attachments are statements, not saves, and a statement leaves the revision alone unless it
 * says otherwise: a triage reading the issue before the sweep recorded its ticket, and saving the whole
 * row after, emptied the reference again — and the next sweep opened a second ticket. The person's
 * transaction reads the issue, the attachment commits on another thread, the decision is written.
 */
@DisplayName("a ticket attached under a triage")
class IssueRevisionTest extends VectispireContextTest {

    @Autowired
    private IssueRepository issues;

    @Autowired
    private IssueTriageService triage;

    @Autowired
    private TransactionTemplate transactions;

    private final ExecutorService sweep = Executors.newSingleThreadExecutor();

    @AfterEach
    void release() {
        sweep.shutdownNow();
    }

    @Test
    @DisplayName("by the sweep: the triage that read the issue before is refused, and the reference stays")
    void theSweepsTicket() {
        long id = issue();

        refusedAround(id, () -> issues.attachTicket(id, "ENG-42", "https://tracker.example/ENG-42"));

        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("ENG-42");
    }

    @Test
    @DisplayName("by a person: the triage that read the issue before is refused, and the reference stays")
    void aPersonsTicket() {
        long id = issue();

        refusedAround(id, () -> issues.attachTicketBy(id, "ENG-43", "https://tracker.example/ENG-43", "bob"));

        IssueEntity stored = issues.findById(id).orElseThrow();
        assertThat(stored.getTicketRef()).isEqualTo("ENG-43");
        assertThat(stored.getTicketAttachedBy()).isEqualTo("bob");
    }

    /** A triage whose transaction read the issue before {@code attach} committed on another thread. */
    private void refusedAround(long id, Runnable attach) {
        assertThatThrownBy(() -> transactions.executeWithoutResult(status -> {
            issues.findById(id).orElseThrow();
            try {
                sweep.submit(attach).get(1, TimeUnit.MINUTES);
            } catch (Exception failed) {
                throw new IllegalStateException("The attachment beside the triage failed.", failed);
            }
            triage.triage(id, new Triage.Request(TriageStatus.AFFECTED, "alice", null, null, null));
        })).isInstanceOf(IssueChangedMeanwhileException.class);
        assertThat(issues.findById(id).orElseThrow().getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
    }

    private long issue() {
        IssueEntity issue = new IssueEntity();
        issue.setType("vulnerability");
        issue.setIdentifier("CVE-2026-0042");
        issue.setFingerprint("fp-revision-" + System.nanoTime());
        issue.setPackageName("openssl");
        issue.setSource("grype");
        issue.setSeverity("high");
        issue.setState("open");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        return issues.save(issue).getId();
    }
}

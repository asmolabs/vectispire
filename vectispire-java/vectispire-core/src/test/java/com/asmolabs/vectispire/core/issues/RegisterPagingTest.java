package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.time.Period;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Paging a register.
 *
 * <h2>The case that decides the design</h2>
 *
 * <p><b>A restricted reader's page is read within its own targets.</b> It used to be read whole and
 * filtered afterwards, with the cursor taken from the rows read so that a page emptied by the filter
 * still pointed further on — and that cursor named, by instant and issue id, an exception the reader
 * could not see: paging one row at a time, a reader of one repository walked every risk acceptance in
 * the estate. Read within the reader's targets, a page never spends its window on somebody else's
 * estate, so the third case below finds the reader's own row at once, and no cursor ever names a row
 * of theirs.
 *
 * <h2>Why a cursor and not an offset</h2>
 *
 * <p>An offset counts rows the caller may not see, so the second page of a restricted reader
 * starts in the middle of somebody else's estate — and the boundary moves every time a pipeline
 * writes. The first case pins what a cursor buys instead: two pages that partition the register,
 * with nothing seen twice and nothing skipped.
 */
@DisplayName("paging a register")
class RegisterPagingTest extends VectispireContextTest {

    @Autowired
    private ExceptionsRegisterService register;

    @Autowired
    private IssueTriageService triage;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("hands back two pages that partition the register")
    void pagesPartitionTheRegister() {
        List<Long> all = excepted(4, repository("app"));

        ExceptionsRegisterService.Register first = register.register(2, null, Visibility.everything());
        assertThat(first.entries()).hasSize(2);
        assertThat(first.nextCursor()).isNotNull();

        ExceptionsRegisterService.Register second =
                register.register(2, first.nextCursor(), Visibility.everything());

        List<Long> seen = new ArrayList<>();
        first.entries().forEach(entry -> seen.add(entry.issueId()));
        second.entries().forEach(entry -> seen.add(entry.issueId()));

        assertThat(seen)
                .as("nothing seen twice, nothing skipped — the whole property an audit register asks for")
                .containsExactlyInAnyOrderElementsOf(all);
    }

    @Test
    @DisplayName("stops when the read runs short, and not before")
    void endsOnAShortRead() {
        excepted(3, repository("app"));

        assertThat(register.register(10, null, Visibility.everything()).nextCursor())
                .as("a short read exhausts the register: there is nothing after it to point at")
                .isNull();
        assertThat(register.register(3, null, Visibility.everything()).nextCursor())
                .as("a full read may hide a continuation, even when it lands exactly")
                .isNotNull();
    }

    @Test
    @DisplayName("reads a restricted reader's page within its targets, never somebody else's window")
    void aRestrictedPageIsReadWithinTheReader() {
        long theirs = repository("theirs");
        long mine = repository("mine");
        // **The register's order is descending, so the last sorted comes first.** The reader's is
        // created first so as to sort behind a whole window of somebody else's estate — the window a
        // read of the whole register spent this page on, handing back a cursor that named their row.
        List<Long> visible = excepted(1, mine);
        excepted(2, theirs);

        Visibility restricted = Visibility.only(List.of(new ScanTarget.Repository(mine)));

        ExceptionsRegisterService.Register page = register.register(2, null, restricted);

        assertThat(page.entries())
                .extracting(ExceptionsRegisterService.ExceptionEntry::issueId)
                .as("the reader's own row, at once")
                .containsExactlyElementsOf(visible);
        assertThat(page.nextCursor())
                .as("a short read within the reader's targets: nothing of theirs left to point at")
                .isNull();
    }

    @Test
    @DisplayName("starts at the newest when the cursor cannot be read")
    void anUnusableCursorStartsOver() {
        excepted(2, repository("app"));

        // The client did not compose this value: it sent back what the server gave it.
        assertThat(register.register(10, "pas-un-curseur", Visibility.everything()).entries())
                .hasSize(2);
        assertThat(register.register(10, "1757836800000:pas-un-nombre", Visibility.everything()).entries())
                .hasSize(2);
    }

    /** {@code count} issues excepted on one repository, oldest first, one second apart. */
    private List<Long> excepted(int count, long repoId) {
        List<Long> ids = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repoId);
            issue.setFingerprint("fp-" + repoId + "-" + index + "-" + System.nanoTime());
            issue.setIdentifier("CVE-2026-" + repoId + index);
            issue.setType(FindingType.VULNERABILITY.wireName());
            issue.setSeverity(Severity.HIGH.wireName());
            issue.setState(IssueState.OPEN.wireName());
            issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
            issue.setIsKev(false);
            issue.setFirstSeenAt(clock.instant());
            issue.setLastSeenAt(clock.instant());
            issue.setTimesSeen(1);
            long id = issues.save(issue).getId();

            triage.triage(
                    id,
                    new Triage.Request(
                            TriageStatus.NOT_AFFECTED, "c.moreau",
                            VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH, "Not reachable.",
                            Period.ofDays(90)),
                    true);
            ids.add(id);
        }
        return ids;
    }

    private long repository(String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.invalid/team/" + name + "-" + System.nanoTime() + ".git");
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }
}

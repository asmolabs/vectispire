package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The rules that decide what happens to a target's backlog.
 *
 * <p>Every one of them fails silently when it is wrong: no exception, no log line, and a
 * dashboard that looks better afterwards. That is why they are tested here, against fakes,
 * rather than only through a scan that would have to be arranged end to end.
 */
@DisplayName("folding findings into the issue history")
class IssueSyncServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-13T10:00:00Z");

    private Issues issues;
    private Findings findings;
    private IssueSyncService service;

    private final List<IssueEntity> stored = new ArrayList<>();
    private final AtomicLong nextId = new AtomicLong(1);

    @BeforeEach
    void wire() {
        issues = mock(Issues.class);
        findings = mock(Findings.class);
        service = new IssueSyncService(issues, findings, Clock.fixed(NOW, ZoneOffset.UTC));

        stored.clear();
        // `saveAll` assigns identifiers, because the service depends on them being there
        // afterwards: it attaches each finding to the issue it belongs to.
        when(issues.saveAll(any())).thenAnswer(call -> {
            List<IssueEntity> batch = call.getArgument(0);
            batch.forEach(issue -> {
                if (issue.getId() == null) {
                    issue.setId(nextId.getAndIncrement());
                }
            });
            return batch;
        });
        when(issues.findByFingerprintIn(any())).thenReturn(List.of());
        when(issues.findOpenByTarget(anyString(), any(), any(), any())).thenReturn(List.of());
    }

    private static ScanEntity scan() {
        ScanEntity scan = new ScanEntity();
        scan.setId(7L);
        scan.setRepoId(3L);
        scan.setBranch("main");
        return scan;
    }

    private static FindingEntity finding(FindingType type, String identifier) {
        FindingEntity finding = new FindingEntity();
        finding.setType(type.wireName());
        finding.setIdentifier(identifier);
        finding.setPackageName("requests");
        finding.setSource("grype");
        finding.setSeverity("high");
        finding.setCreatedAt(NOW);
        return finding;
    }

    private static IssueEntity openIssue(String fingerprint, FindingType type) {
        IssueEntity issue = new IssueEntity();
        issue.setId(100L);
        issue.setFingerprint(fingerprint);
        issue.setType(type.wireName());
        issue.setState("open");
        issue.setTimesSeen(4);
        issue.setTriageStatus(TriageStatus.NOT_AFFECTED.wireName());
        issue.setFirstSeenAt(NOW.minusSeconds(86400));
        issue.setLastSeenAt(NOW.minusSeconds(86400));
        return issue;
    }

    @Nested
    @DisplayName("what gets resolved")
    class Resolution {

        @Test
        @DisplayName("a type nobody looked at keeps its issues")
        void unscannedTypesAreUntouched() {
            // The pivot. "No secret findings because nobody looked" must leave the secret issues
            // alone; only "the scanner ran and found nothing" may resolve them. Deriving the set
            // from the findings present cannot tell the two apart.
            service.sync(scan(), List.of(), Set.of(), Map.of(), null);

            verify(issues, never()).findOpenByTarget(anyString(), any(), any(), any());
        }

        @Test
        @DisplayName("a scanner that ran and found nothing resolves its own type, and only its own")
        void scannedTypesResolve() {
            IssueEntity goneSecret = openIssue("f-secret", FindingType.SECRET);
            when(issues.findOpenByTarget(anyString(), any(), any(), any())).thenReturn(List.of(goneSecret));

            IssueSyncService.SyncResult result =
                    service.sync(scan(), List.of(), Set.of(FindingType.SECRET), Map.of(), null);

            assertThat(result.resolved()).isEqualTo(1);
            assertThat(goneSecret.getState()).isEqualTo("resolved");
            assertThat(goneSecret.getResolvedAt()).isEqualTo(NOW);
        }

        @Test
        @DisplayName("an issue seen again is not resolved")
        void seenIssuesSurvive() {
            FindingEntity seen = finding(FindingType.VULNERABILITY, "CVE-1");
            ScanEntity scan = scan();

            // The same fingerprint the service will compute for that finding.
            IssueSyncService.SyncResult first = service.sync(scan, List.of(seen), Set.of(), Map.of(), null);
            String fingerprint = first.newIssues().getFirst().getFingerprint();

            IssueEntity existing = openIssue(fingerprint, FindingType.VULNERABILITY);
            when(issues.findByFingerprintIn(any())).thenReturn(List.of(existing));
            when(issues.findOpenByTarget(anyString(), any(), any(), any())).thenReturn(List.of(existing));

            IssueSyncService.SyncResult second = service.sync(
                    scan, List.of(finding(FindingType.VULNERABILITY, "CVE-1")),
                    Set.of(FindingType.VULNERABILITY), Map.of(), null);

            assertThat(second.resolved()).isZero();
            assertThat(second.stillOpen()).isEqualTo(1);
            assertThat(existing.getTimesSeen()).isEqualTo(5);
        }
    }

    @Nested
    @DisplayName("what a repeated finding changes")
    class Refresh {

        @Test
        @DisplayName("one issue, however many times the scan saw it")
        void occurrencesCollapseIntoOneIssue() {
            // The same CVE at two places in one package is one issue with two occurrences, not
            // two issues.
            List<FindingEntity> twice =
                    List.of(finding(FindingType.VULNERABILITY, "CVE-1"), finding(FindingType.VULNERABILITY, "CVE-1"));

            IssueSyncService.SyncResult result = service.sync(scan(), twice, Set.of(), Map.of(), null);

            assertThat(result.created()).isEqualTo(1);
            // Both occurrences point at it, which is what makes the scan detail show them.
            assertThat(twice).allSatisfy(finding -> assertThat(finding.getIssueId()).isNotNull());
        }

        @Test
        @DisplayName("an absent value does not erase what an earlier scan established")
        void nullsDoNotOverwrite() {
            // Enrichment runs *after* this reconciliation for a brand new finding, so a missing
            // score on this pass must not wipe the one already stored.
            IssueSyncService.SyncResult first =
                    service.sync(scan(), List.of(finding(FindingType.VULNERABILITY, "CVE-1")), Set.of(), Map.of(), null);
            IssueEntity existing = first.newIssues().getFirst();
            existing.setEpssScore(0.97);
            existing.setIsKev(true);
            when(issues.findByFingerprintIn(any())).thenReturn(List.of(existing));

            FindingEntity unenriched = finding(FindingType.VULNERABILITY, "CVE-1");
            service.sync(scan(), List.of(unenriched), Set.of(), Map.of(), null);

            assertThat(existing.getEpssScore()).isEqualTo(0.97);
            // False must not un-flag an exploited vulnerability, or the gate stops failing on it.
            assertThat(existing.getIsKev()).isTrue();
        }
    }

    @Nested
    @DisplayName("reopening")
    class Reopen {

        @Test
        @DisplayName("clears a fixed triage, because the fact just contradicted it")
        void fixedTriageIsCleared() {
            IssueSyncService.SyncResult first =
                    service.sync(scan(), List.of(finding(FindingType.VULNERABILITY, "CVE-1")), Set.of(), Map.of(), null);
            IssueEntity resolvedIssue = first.newIssues().getFirst();
            resolvedIssue.setState("resolved");
            resolvedIssue.setTriageStatus(TriageStatus.FIXED.wireName());
            resolvedIssue.setTriagedBy("alice");
            when(issues.findByFingerprintIn(any())).thenReturn(List.of(resolvedIssue));

            IssueSyncService.SyncResult result = service.sync(
                    scan(), List.of(finding(FindingType.VULNERABILITY, "CVE-1")), Set.of(), Map.of(), null);

            assertThat(result.reopened()).isEqualTo(1);
            assertThat(resolvedIssue.getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
            assertThat(resolvedIssue.getTriagedBy()).isNull();
        }

        @Test
        @DisplayName("keeps a not_affected judgement, which is about exposure and not presence")
        void argumentsSurvive() {
            // The package coming back does not contradict "the vulnerable path is unreachable in
            // our configuration". Clearing it would make somebody re-argue the same exemption.
            IssueSyncService.SyncResult first =
                    service.sync(scan(), List.of(finding(FindingType.VULNERABILITY, "CVE-1")), Set.of(), Map.of(), null);
            IssueEntity resolvedIssue = first.newIssues().getFirst();
            resolvedIssue.setState("resolved");
            resolvedIssue.setTriageStatus(TriageStatus.NOT_AFFECTED.wireName());
            resolvedIssue.setTriagedBy("alice");
            when(issues.findByFingerprintIn(any())).thenReturn(List.of(resolvedIssue));

            service.sync(scan(), List.of(finding(FindingType.VULNERABILITY, "CVE-1")), Set.of(), Map.of(), null);

            assertThat(resolvedIssue.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
            assertThat(resolvedIssue.getTriagedBy()).isEqualTo("alice");
        }
    }

    @Nested
    @DisplayName("the pre-commit hook")
    class Hook {

        @Test
        @DisplayName("sees the result while the transaction is still open")
        void runsBeforeReturning() {
            AtomicReference<IssueSyncService.SyncResult> seen = new AtomicReference<>();

            service.sync(scan(), List.of(finding(FindingType.SECRET, "aws-key")), Set.of(), Map.of(), seen::set);

            assertThat(seen.get()).isNotNull();
            assertThat(seen.get().created()).isEqualTo(1);
        }

        @Test
        @DisplayName("a hook that throws does not cost the scan its results")
        void failureIsAbsorbed() {
            // The results are what has value in this transaction. Losing them because a
            // notification could not be queued would be the wrong trade.
            IssueSyncService.SyncResult result = service.sync(
                    scan(),
                    List.of(finding(FindingType.SECRET, "aws-key")),
                    Set.of(),
                    Map.of(),
                    ignored -> {
                        throw new IllegalStateException("outbox unavailable");
                    });

            assertThat(result.created()).isEqualTo(1);
        }
    }

    @Test
    @DisplayName("an unknown finding type is refused rather than fingerprinted as itself")
    void unknownTypeIsRefused() {
        // It would fingerprint to something no existing issue matches, so every scan would
        // create it anew and resolve the previous one — a backlog that churns without ever
        // being wrong on screen.
        FindingEntity alien = finding(FindingType.VULNERABILITY, "CVE-1");
        alien.setType("invented");

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> service.sync(scan(), List.of(alien), Set.of(), Map.of(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("invented");
    }

    @Test
    @DisplayName("the scan carries the counts it produced")
    void scanRecordsItsCounts() {
        ScanEntity scan = scan();
        IssueEntity gone = openIssue("f-old", FindingType.SECRET);
        when(issues.findOpenByTarget(anyString(), any(), any(), any())).thenReturn(List.of(gone));

        service.sync(scan, List.of(finding(FindingType.SECRET, "aws-key")), Set.of(FindingType.SECRET), Map.of(), null);

        assertThat(scan.getNewIssuesCount()).isEqualTo(1);
        assertThat(scan.getResolvedIssuesCount()).isEqualTo(1);
    }
}

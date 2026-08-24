package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.services.TriageHistory;
import com.asmolabs.vectispire.core.services.TriageHistoryCsv;
import com.asmolabs.vectispire.core.services.TriageHistoryReport;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.data.domain.Limit;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The trail that shows a finding was taken into account.
 *
 * <p><b>Not another view of the backlog.</b> The issues screen answers "what is open now"; this
 * one answers "what did we see, when, on which version, and what did we decide about it" — the
 * question asked by somebody who has to be convinced after the fact, and who was not there.
 *
 * <p>Three facts are joined here that live apart in the schema, and the joining is the whole
 * feature: a scan carries the version of the tree it read, a finding links that scan to an
 * issue, and a triage event carries the decision taken on that issue. Separately each is
 * unremarkable; together they are "CVE-2026-1 detected on 2.4.1 the 3rd, accepted the 7th by
 * alice because the vulnerable code is not reachable, still absent from 2.5.0".
 *
 * <p><b>The decisions are not filtered by the scan.</b> An acceptance recorded in March still
 * governs the scan that runs in June, so a decision is shown with the issue it applies to
 * regardless of when it was taken. Keying decisions to scans would show each one once and lose
 * it from every later page.
 */
@RestController
@RequestMapping("/api/v1/history")
@RequiresAccount
public class HistoryController {

    /**
     * The trail is a report, not a feed: a target with a thousand scans is read by period, and
     * a page that returned all of them would be neither faster nor more useful.
     */
    private static final int MAX_SCANS = 200;

    private static final int MAX_FINDINGS = 500;

    private final GitRepositories repositories;
    private final Scans scans;
    private final Findings findings;
    private final Issues issues;
    private final TriageEvents events;
    private final VisibilityService visibility;
    private final Clock clock;

    public HistoryController(
            GitRepositories repositories,
            Scans scans,
            Findings findings,
            Issues issues,
            TriageEvents events,
            VisibilityService visibility,
            Clock clock) {
        this.repositories = repositories;
        this.scans = scans;
        this.findings = findings;
        this.issues = issues;
        this.events = events;
        this.visibility = visibility;
        this.clock = clock;
    }

    @GetMapping("/repositories")
    public List<TriageHistory.Repository> repositories(@AuthenticationPrincipal VectispirePrincipal principal) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());

        return repositories.findAll().stream()
                .filter(repository -> allowed.permits(new ScanTarget.Repository(repository.getId())))
                .map(this::rowOf)
                .sorted(Comparator.comparing(
                        TriageHistory.Repository::lastScanAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
    }

    @GetMapping("/repositories/{id}")
    public TriageHistory.Dossier dossier(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long id,
            @RequestParam(required = false, defaultValue = "50") int limit) {

        RepositoryEntity repository = visible(principal, id);
        return new TriageHistory.Dossier(rowOf(repository), scanRows(id, limit), clock.instant());
    }

    @GetMapping(value = "/repositories/{id}/export.csv", produces = "text/csv")
    public ResponseEntity<byte[]> csv(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {

        RepositoryEntity repository = visible(principal, id);
        String content = TriageHistoryCsv.render(rowOf(repository), scanRows(id, MAX_SCANS));
        return download(
                content.getBytes(StandardCharsets.UTF_8),
                MediaType.parseMediaType("text/csv"),
                "vectispire-history-" + id + ".csv");
    }

    @GetMapping(value = "/repositories/{id}/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {

        RepositoryEntity repository = visible(principal, id);
        byte[] document = TriageHistoryReport.render(rowOf(repository), scanRows(id, MAX_SCANS), clock.instant());
        return download(document, MediaType.APPLICATION_PDF, "vectispire-history-" + id + ".pdf");
    }

    /**
     * <b>An attachment, not an inline document.</b> Without the disposition a browser renders
     * the payload in the tab, which is how the OpenVEX export used to arrive — a document meant
     * to be filed, displayed as text and never saved.
     */
    private static ResponseEntity<byte[]> download(byte[] body, MediaType type, String filename) {
        return ResponseEntity.ok()
                .contentType(type)
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(filename).build().toString())
                .body(body);
    }

    private RepositoryEntity visible(VectispirePrincipal principal, long id) {
        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));
        // 404 rather than 403 when it exists but is not visible — see `Visibilities`.
        Visibilities.requireVisible(
                new ScanTarget.Repository(repository.getId()),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        return repository;
    }

    private TriageHistory.Repository rowOf(RepositoryEntity repository) {
        List<ScanEntity> history = scans.findHistory(repository.getId(), null, Limit.of(MAX_SCANS));

        // The most recent scan that actually read a version, not the most recent scan: a failed
        // clone would otherwise blank the version the day it happens, and a target would appear
        // to have lost the identity it still has.
        String version = history.stream()
                .map(ScanEntity::getVersion)
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);
        String type = history.stream()
                .map(ScanEntity::getProjectType)
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);

        return new TriageHistory.Repository(
                repository.getId(),
                repository.getName() == null ? repository.getUrl() : repository.getName(),
                repository.getUrl(),
                repository.getBranch(),
                version,
                type,
                history.size(),
                history.stream().map(ScanEntity::getCreatedAt).max(Comparator.naturalOrder()).orElse(null),
                issues.countByStateAndRepository(IssueState.OPEN.wireName(), repository.getId()),
                events.countForRepository(repository.getId()));
    }

    private List<TriageHistory.Scan> scanRows(long repositoryId, int limit) {
        List<ScanEntity> history =
                scans.findHistory(repositoryId, null, Limit.of(Math.clamp(limit, 1, MAX_SCANS)));

        // **Everything the page needs, in three queries rather than three per scan.** The issues
        // and their decisions are fetched once for the whole page: asking per scan turns a
        // fifty-scan dossier into a hundred and fifty round trips, which is invisible on a demo
        // database and is the difference between a page and a timeout on a real one.
        Map<Long, List<FindingEntity>> findingsByScan = history.isEmpty()
                ? Map.of()
                : findings.findByScanIdIn(history.stream().map(ScanEntity::getId).toList()).stream()
                        .collect(Collectors.groupingBy(FindingEntity::getScanId));

        Set<Long> issueIds = findingsByScan.values().stream()
                .flatMap(List::stream)
                .map(FindingEntity::getIssueId)
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());

        Map<Long, IssueEntity> issuesById = issueIds.isEmpty()
                ? Map.of()
                : issues.findAllById(issueIds).stream()
                        .collect(Collectors.toMap(IssueEntity::getId, issue -> issue));

        Map<Long, List<TriageEventEntity>> decisionsByIssue = issueIds.isEmpty()
                ? Map.of()
                : events.findForIssues(issueIds).stream()
                        .collect(Collectors.groupingBy(TriageEventEntity::getIssueId));

        Map<Long, String> versionByScan = new LinkedHashMap<>();
        history.forEach(scan -> versionByScan.put(scan.getId(), scan.getVersion()));

        List<TriageHistory.Scan> rows = new ArrayList<>(history.size());
        for (ScanEntity scan : history) {
            List<TriageHistory.ObservedIssue> observed = new ArrayList<>();
            java.util.Set<Long> already = new java.util.HashSet<>();

            for (FindingEntity finding : findingsByScan.getOrDefault(scan.getId(), List.of())) {
                IssueEntity issue = finding.getIssueId() == null ? null : issuesById.get(finding.getIssueId());
                // One line per issue, not per finding: a scan reports the same issue once per
                // occurrence, and a trail listing it four times reads as four decisions to take.
                if (issue == null || !already.add(issue.getId()) || observed.size() >= MAX_FINDINGS) {
                    continue;
                }
                observed.add(observedOf(issue, decisionsByIssue.getOrDefault(issue.getId(), List.of()), versionByScan));
            }

            rows.add(new TriageHistory.Scan(
                    scan.getId(),
                    scan.getStatus(),
                    scan.getBranch(),
                    scan.getVersion(),
                    scan.getProjectType(),
                    scan.getCreatedAt(),
                    scan.getDurationMs(),
                    scan.getFindingsCount(),
                    scan.getNewIssuesCount(),
                    scan.getResolvedIssuesCount(),
                    scan.getError(),
                    List.copyOf(observed)));
        }
        return List.copyOf(rows);
    }

    private static TriageHistory.ObservedIssue observedOf(
            IssueEntity issue, List<TriageEventEntity> decisions, Map<Long, String> versionByScan) {

        return new TriageHistory.ObservedIssue(
                issue.getId(),
                issue.getType(),
                issue.getIdentifier(),
                issue.getSeverity(),
                issue.getPackageName(),
                issue.getPackageVersion(),
                issue.getFilePath(),
                issue.getState(),
                issue.getTriageStatus(),
                issue.getFirstSeenAt(),
                issue.getResolvedAt(),
                decisions.stream()
                        .map(event -> new TriageHistory.Decision(
                                event.getFromStatus(),
                                event.getToStatus(),
                                event.getJustification(),
                                event.getComment(),
                                event.getActor(),
                                event.getOrigin(),
                                event.getOccurredAt(),
                                event.getExpiresAt(),
                                event.getScanId(),
                                event.getScanId() == null ? null : versionByScan.get(event.getScanId())))
                        .toList());
    }
}

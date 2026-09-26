package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.services.targets.RepositoryView;
import com.asmolabs.vectispire.core.services.targets.TargetCatalog;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.settings.BrandingProperties;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;

/**
 * The trail that shows a finding was taken into account, joined from the three tables it lives
 * apart in — see {@code HistoryController} for what the trail is for.
 *
 * <p><b>Every entry point takes the caller's visibility</b> and refuses a repository they were not
 * given in the words an absent one gets, so the screen, the CSV and the PDF cannot disagree about
 * who may read them.
 */
@Service
public class HistoryQueryService {

    /**
     * The trail is a report, not a feed: a target with a thousand scans is read by period, and
     * a page that returned all of them would be neither faster nor more useful.
     */
    private static final int MAX_SCANS = 200;

    private static final int MAX_FINDINGS = 500;

    private final TargetCatalog targets;
    private final Scans scans;
    private final Findings findings;
    private final Issues issues;
    private final TriageEvents events;
    private final BrandingProperties branding;
    private final Clock clock;

    public HistoryQueryService(
            TargetCatalog targets,
            Scans scans,
            Findings findings,
            Issues issues,
            TriageEvents events,
            BrandingProperties branding,
            Clock clock) {
        this.targets = targets;
        this.scans = scans;
        this.findings = findings;
        this.issues = issues;
        this.events = events;
        this.branding = branding;
        this.clock = clock;
    }

    public List<TriageHistory.Repository> repositories(Visibility allowed) {
        return targets.repositories().stream()
                .filter(repository -> allowed.permits(new ScanTarget.Repository(repository.id())))
                .map(this::rowOf)
                .sorted(Comparator.comparing(
                        TriageHistory.Repository::lastScanAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();
    }

    public TriageHistory.Dossier dossier(long id, int limit, Visibility allowed) {
        RepositoryView repository = visible(id, allowed);
        return new TriageHistory.Dossier(rowOf(repository), scanRows(id, limit), clock.instant());
    }

    /** The CSV export, as UTF-8 bytes. */
    public byte[] csv(long id, Visibility allowed) {
        RepositoryView repository = visible(id, allowed);
        return TriageHistoryCsv.render(rowOf(repository), scanRows(id, MAX_SCANS)).getBytes(StandardCharsets.UTF_8);
    }

    public byte[] pdf(long id, Visibility allowed) {
        RepositoryView repository = visible(id, allowed);
        return TriageHistoryReport.render(rowOf(repository), scanRows(id, MAX_SCANS), clock.instant(), branding.name());
    }

    private RepositoryView visible(long id, Visibility allowed) {
        // 404 rather than 403 when it exists but is not visible, in the same words as when it does
        // not exist — see `RowVisibility`.
        return RowVisibility.requireVisibleRepository(targets.repository(id).orElse(null), id, allowed);
    }

    private TriageHistory.Repository rowOf(RepositoryView repository) {
        List<ScanEntity> history = scans.findHistory(repository.id(), null, Limit.of(MAX_SCANS));

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
                repository.id(),
                repository.name() == null ? RepositoryUrl.redact(repository.url()) : repository.name(),
                // Masked here, at the source of the trail, so the screen, the CSV and the PDF
                // built from it all carry the same safe form.
                RepositoryUrl.redact(repository.url()),
                repository.branch(),
                version,
                type,
                history.size(),
                history.stream().map(ScanEntity::getCreatedAt).max(Comparator.naturalOrder()).orElse(null),
                issues.countByStateAndRepository(IssueState.OPEN.wireName(), repository.id()),
                events.countForRepository(repository.id()));
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
                .filter(Objects::nonNull)
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
            Set<Long> already = new HashSet<>();

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

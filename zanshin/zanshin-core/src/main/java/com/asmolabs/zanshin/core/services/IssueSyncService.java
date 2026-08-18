package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.IssueFingerprint;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Repositories;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Folding one scan's findings into the issue history.
 *
 * <p><b>Called only for a completed scan.</b> A scan that failed or was interrupted observed
 * nothing, and treating that as evidence of absence marks a whole target's backlog resolved.
 *
 * <p>The service holds no session of its own: it runs inside the caller's transaction. That is
 * what makes the {@code beforeCommit} guarantee possible at all.
 */
@Service
public class IssueSyncService {

    private static final Logger log = LoggerFactory.getLogger(IssueSyncService.class);

    private final Repositories.Issues issues;
    private final Repositories.Findings findings;
    private final Clock clock;

    public IssueSyncService(Repositories.Issues issues, Repositories.Findings findings, Clock clock) {
        this.issues = issues;
        this.findings = findings;
        this.clock = clock;
    }

    /**
     * @param newIssues the issues themselves, not only the counts: a notification has to say
     *     <em>what</em> appeared, and rebuilding the list afterwards would mean re-deducing
     *     "which ones are new" — the one thing this method already knows for certain
     */
    public record SyncResult(
            int created,
            int resolved,
            int reopened,
            int stillOpen,
            List<IssueEntity> newIssues,
            List<IssueEntity> reopenedIssues) {}

    /**
     * @param scannedTypes the finding types this scan <b>actually looked at</b>, supplied by the
     *     caller and never inferred from the findings present.
     *     <p>This is the pivot of the whole resolution pass. "The secrets scanner ran and found
     *     nothing" must resolve the secret issues, while "no secret findings because nobody
     *     looked" must leave them alone. Deriving the set from the findings cannot tell the two
     *     apart, and getting it wrong silently resolves a type's entire history — no error, no
     *     log line (decision 0007).
     * @param descriptions text by identifier, when the scanner supplies any
     * @param beforeCommit called with the result <b>while the transaction is still open</b>.
     *     Exists for one caller and one reason: the notification outbox has to become durable at
     *     the same instant as the issues it describes. Queueing it after the return would leave
     *     the window in which a crash loses the notification — the very defect an outbox removes
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public SyncResult sync(
            ScanEntity scan,
            List<FindingEntity> scanFindings,
            Set<FindingType> scannedTypes,
            Map<String, String> descriptions,
            Consumer<SyncResult> beforeCommit) {

        Instant moment = clock.instant();
        ScanTarget target = targetOf(scan);

        // One finding can repeat within a scan — the same CVE at two places in one package. The
        // issue is one; its occurrences are several.
        Map<String, List<FindingEntity>> byFingerprint = new LinkedHashMap<>();
        for (FindingEntity finding : scanFindings) {
            byFingerprint
                    .computeIfAbsent(fingerprintOf(target, finding), key -> new ArrayList<>())
                    .add(finding);
        }

        Map<String, IssueEntity> existing = byFingerprint.isEmpty()
                ? Map.of()
                : issues.findByFingerprintIn(byFingerprint.keySet()).stream()
                        .collect(Collectors.toMap(IssueEntity::getFingerprint, issue -> issue, (a, b) -> a));

        List<IssueEntity> created = new ArrayList<>();
        List<IssueEntity> reopened = new ArrayList<>();
        List<IssueEntity> touched = new ArrayList<>(byFingerprint.size());

        for (Map.Entry<String, List<FindingEntity>> entry : byFingerprint.entrySet()) {
            FindingEntity finding = entry.getValue().getFirst();
            IssueEntity issue = existing.get(entry.getKey());

            if (issue == null) {
                issue = create(scan, entry.getKey(), finding, moment);
                issue.setDescription(descriptions.get(orEmpty(finding.getIdentifier())));
                created.add(issue);
            } else {
                if (IssueState.RESOLVED.wireName().equals(issue.getState())) {
                    reopen(issue);
                    reopened.add(issue);
                }
                refresh(issue, finding, scan, moment);
                if (issue.getDescription() == null) {
                    issue.setDescription(descriptions.get(orEmpty(finding.getIdentifier())));
                }
            }
            touched.add(issue);
        }

        // Saved before the occurrences are attached: a brand new issue has no identifier yet,
        // and a finding cannot point at nothing.
        List<IssueEntity> saved = issues.saveAll(touched);
        Map<String, Long> idByFingerprint =
                saved.stream().collect(Collectors.toMap(IssueEntity::getFingerprint, IssueEntity::getId, (a, b) -> a));

        for (Map.Entry<String, List<FindingEntity>> entry : byFingerprint.entrySet()) {
            Long issueId = idByFingerprint.get(entry.getKey());
            entry.getValue().forEach(occurrence -> occurrence.setIssueId(issueId));
        }

        // **The findings themselves are written here**, and forgetting it showed on screen: a
        // scan's detail announced eight findings and displayed none. Issues carry a target's
        // history; findings say what one scan observed — the material of the scan detail, of the
        // SARIF export, and of the proof that an issue existed on a given date.
        if (!scanFindings.isEmpty()) {
            findings.saveAll(scanFindings);
        }

        int resolved = resolveDisappeared(scan, scannedTypes, byFingerprint.keySet(), moment);

        scan.setNewIssuesCount(created.size());
        scan.setResolvedIssuesCount(resolved);

        SyncResult result = new SyncResult(
                created.size(),
                resolved,
                reopened.size(),
                byFingerprint.size() - created.size() - reopened.size(),
                List.copyOf(created),
                List.copyOf(reopened));

        if (beforeCommit != null) {
            try {
                beforeCommit.accept(result);
            } catch (RuntimeException failed) {
                // A failing hook must not cost the scan's results, which are what has value in
                // this transaction. The caller commits anyway, without what the hook wanted to
                // add — and says so, because a notification that silently never happens is the
                // kind of absence nobody reports.
                log.warn("The post-sync hook failed for scan {}; its results are kept", scan.getId(), failed);
            }
        }

        return result;
    }

    /**
     * Resolves the issues this scan did not see again.
     *
     * <p>Restricted to the types the scan looked at, and to nothing at all when it looked at
     * none — the guard that makes a malformed call harmless rather than destructive.
     */
    private int resolveDisappeared(ScanEntity scan, Set<FindingType> scannedTypes, Set<String> seen, Instant moment) {
        if (scannedTypes.isEmpty()) {
            return 0;
        }

        List<String> types = scannedTypes.stream().map(FindingType::wireName).toList();
        List<IssueEntity> disappeared = issues
                .findOpenByTarget(IssueState.OPEN.wireName(), types, scan.getRepoId(), scan.getContainerId())
                .stream()
                .filter(issue -> !seen.contains(issue.getFingerprint()))
                .toList();

        disappeared.forEach(issue -> {
            issue.setState(IssueState.RESOLVED.wireName());
            issue.setResolvedAt(moment);
        });
        issues.saveAll(disappeared);
        return disappeared.size();
    }

    private IssueEntity create(ScanEntity scan, String fingerprint, FindingEntity finding, Instant moment) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(scan.getRepoId());
        issue.setContainerId(scan.getContainerId());
        issue.setFingerprint(fingerprint);
        issue.setType(finding.getType());
        issue.setIdentifier(finding.getIdentifier());
        issue.setPurl(finding.getPurl());
        issue.setPackageName(finding.getPackageName());
        issue.setFilePath(finding.getFilePath());
        issue.setState(IssueState.OPEN.wireName());
        issue.setFirstSeenAt(moment);
        issue.setLastSeenAt(moment);
        issue.setFirstSeenScanId(scan.getId());
        issue.setLastSeenScanId(scan.getId());
        issue.setTimesSeen(1);
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        copyRefreshedFields(issue, finding, true);
        return issue;
    }

    private void refresh(IssueEntity issue, FindingEntity finding, ScanEntity scan, Instant moment) {
        copyRefreshedFields(issue, finding, false);
        issue.setLastSeenAt(moment);
        issue.setLastSeenScanId(scan.getId());
        issue.setTimesSeen(issue.getTimesSeen() + 1);
        issue.setState(IssueState.OPEN.wireName());
        issue.setResolvedAt(null);
    }

    /**
     * The fields a new finding refreshes on an existing issue.
     *
     * <p>{@code packageVersion} is among them although it is <b>excluded from the
     * fingerprint</b>, and that is exactly the intent: an outdated dependency that stays
     * outdated across three version bumps is <em>one</em> issue whose displayed version follows,
     * not three whose triage evaporates on every patch release.
     *
     * <p>{@code overwriteNulls} is false on a refresh. Enrichment — the exploitation score, the
     * exploited-in-the-wild flag — runs <em>after</em> this reconciliation for a brand new
     * finding, so an absent value on this pass must not erase what an earlier scan established.
     * On creation there is nothing to erase, so the null is the honest value.
     */
    private static void copyRefreshedFields(IssueEntity issue, FindingEntity finding, boolean overwriteNulls) {
        set(finding.getPackageVersion(), issue::setPackageVersion, overwriteNulls);
        set(finding.getLine(), issue::setLine, overwriteNulls);
        // Skipped when null like the rest, and for a reason of its own: a container scan does
        // not tell direct from transitive, and must not erase what a repository scan established.
        set(finding.getIsDirectDependency(), issue::setIsDirectDependency, overwriteNulls);
        set(finding.getSeverity(), issue::setSeverity, overwriteNulls);
        set(finding.getSource(), issue::setSource, overwriteNulls);
        set(finding.getEpssScore(), issue::setEpssScore, overwriteNulls);
        set(finding.getCvssScore(), issue::setCvssScore, overwriteNulls);
        set(finding.getCvssVector(), issue::setCvssVector, overwriteNulls);
        set(finding.getFixState(), issue::setFixState, overwriteNulls);
        set(finding.getFixVersions(), issue::setFixVersions, overwriteNulls);
        set(finding.getLink(), issue::setLink, overwriteNulls);
        // Both columns are non-nullable, so there is no absent value to skip — but false must
        // not overwrite true on a refresh. Enrichment sets this flag *after* reconciliation, so
        // a second scan arriving before enrichment would otherwise un-flag an exploited
        // vulnerability, and the gate would stop failing on it.
        if (overwriteNulls || finding.getIsKev()) {
            issue.setIsKev(finding.getIsKev());
        }
    }

    private static <T> void set(T value, Consumer<T> target, boolean overwriteNulls) {
        if (value != null || overwriteNulls) {
            target.accept(value);
        }
    }

    /**
     * Reopening a resolved issue that has come back.
     *
     * <p><b>Only a {@code fixed} triage is cleared.</b> It has just been factually contradicted,
     * and leaving it would hide a regression behind a stale decision. A {@code not_affected}
     * judgement is about the code's exposure, not about the package's presence — it survives,
     * and stays visible in the triage history for review.
     */
    private static void reopen(IssueEntity issue) {
        if (TriageStatus.FIXED.wireName().equals(issue.getTriageStatus())) {
            issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
            issue.setTriageJustification(null);
            issue.setTriagedAt(null);
            issue.setTriagedBy(null);
        }
    }

    private static String fingerprintOf(ScanTarget target, FindingEntity finding) {
        FindingType type = FindingType.fromWireName(finding.getType())
                .orElseThrow(() -> new IllegalStateException(
                        "Unknown finding type \"" + finding.getType() + "\": it would fingerprint as itself and "
                                + "never match an existing issue."));

        return IssueFingerprint.of(new IssueFingerprint.Input(
                target,
                type,
                finding.getIdentifier(),
                finding.getPurl(),
                finding.getPackageName(),
                finding.getFilePath()));
    }

    private static ScanTarget targetOf(ScanEntity scan) {
        return Optional.ofNullable(scan.getRepoId())
                .<ScanTarget>map(ScanTarget.Repository::new)
                .orElseGet(() -> new ScanTarget.Container(
                        Optional.ofNullable(scan.getContainerId())
                                .orElseThrow(() -> new IllegalStateException(
                                        "Scan " + scan.getId() + " belongs to no target."))));
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }
}

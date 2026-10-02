package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueFingerprint;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventRaised;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.ObservedFinding;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.springframework.context.ApplicationEventPublisher;
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
 *
 * <p><b>It reads the findings, and writes only issues.</b> The findings are the scan's rows, and
 * {@code scanning} writes them, pointing each at the issue this answers for it; so are the scan's
 * counts. The sync used to take the scan's entities and write both, which is how {@code scanning}
 * and {@code issues} came to use each other (decision 0029). It is reached through {@link
 * IssueBacklog}, {@code scanning}'s {@code Backlog} port.
 */
@Service
public class IssueSyncService {

    /** Fingerprints per lookup: far under every engine's bind-parameter ceiling. */
    private static final int FINGERPRINT_BATCH = 1_000;

    private final IssueRepository issues;
    private final Clock clock;
    /** Where a new leak is raised for the SIEM export — an event, so that this module does not depend on it (decision 0033). */
    private final ApplicationEventPublisher events;

    public IssueSyncService(IssueRepository issues, Clock clock, ApplicationEventPublisher events) {
        this.issues = issues;
        this.clock = clock;
        this.events = events;
    }

    /**
     * @param newIssues the issues themselves, not only the counts: a notification has to say
     *     <em>what</em> appeared, and rebuilding the list afterwards would mean re-deducing
     *     "which ones are new" — the one thing this method already knows for certain
     * @param issueIds the issue each finding is an occurrence of, in the order the findings were
     *     given — what the scan's rows point at
     */
    public record SyncResult(
            int created,
            int resolved,
            int reopened,
            int stillOpen,
            List<IssueEntity> newIssues,
            List<IssueEntity> reopenedIssues,
            List<Long> issueIds) {}

    /**
     * @param scannedTypes the finding types this scan <b>actually looked at</b>, supplied by the
     *     caller and never inferred from the findings present.
     *     <p>This is the pivot of the whole resolution pass. "The secrets scanner ran and found
     *     nothing" must resolve the secret issues, while "no secret findings because nobody
     *     looked" must leave them alone. Deriving the set from the findings cannot tell the two
     *     apart, and getting it wrong silently resolves a type's entire history — no error, no
     *     log line (decision 0007).
     * @param descriptions text by identifier — the advisory prose an enrichment pass looked up.
     *     Only vulnerabilities have any; see {@link #describe} for what the others get
     * @param beforeCommit called with the result <b>while the transaction is still open</b>.
     *     Exists for one caller and one reason: the notification outbox has to become durable at
     *     the same instant as the issues it describes. Queueing it after the return would leave
     *     the window in which a crash loses the notification — the very defect an outbox removes
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public SyncResult sync(
            long scanId,
            ScanTarget scanTarget,
            List<ObservedFinding> scanFindings,
            Set<FindingType> scannedTypes,
            Map<String, String> descriptions,
            Consumer<SyncResult> beforeCommit) {
        return sync(scanId, scanTarget, scanFindings, scannedTypes, Set.of(), descriptions, beforeCommit);
    }

    /**
     * @param scannedTools the tool keys of the plugins that <b>produced</b> a report in this scan
     *     ({@code ToolKeys.plugin}). A tool-scoped type is resolved by these and never by type: a
     *     plugin that was not applicable, or failed, is not among them, and its issues stay as they
     *     are — the third state and the absent one, read the same way here and told apart on the scan
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public SyncResult sync(
            long scanId,
            ScanTarget scanTarget,
            List<ObservedFinding> scanFindings,
            Set<FindingType> scannedTypes,
            Set<String> scannedTools,
            Map<String, String> descriptions,
            Consumer<SyncResult> beforeCommit) {
        return fold(scanId, requireTarget(scanId, scanTarget), scanFindings, scannedTypes, scannedTools, null,
                descriptions, beforeCommit);
    }

    /**
     * Folds an imported SARIF report into the target's backlog — the same reconciliation as a scan's,
     * with no scan: an imported issue's first and last sightings name no scan, and the import record
     * ({@code t_sarif_import}) is its dated evidence.
     *
     * @param importSource the declared source's slug, kept on every issue it touches as provenance
     * @param tools the tool keys the report covers ({@code ToolKeys.imported}); each resolves its own
     *     open issues on the target that this report did not carry, and nothing else
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public SyncResult syncImport(ScanTarget target, String importSource, Set<String> tools, List<ObservedFinding> findings) {
        if (target == null) {
            throw new IllegalStateException("An import belongs to a target.");
        }
        return fold(null, target, findings, Set.of(), tools, importSource, Map.of(), null);
    }

    private SyncResult fold(
            Long scanId,
            ScanTarget target,
            List<ObservedFinding> scanFindings,
            Set<FindingType> scannedTypes,
            Set<String> scannedTools,
            String importSource,
            Map<String, String> descriptions,
            Consumer<SyncResult> beforeCommit) {

        Instant moment = clock.instant();

        // One finding can repeat within a scan — the same CVE at two places in one package. The
        // issue is one; its occurrences are several. The positions are kept to answer, per finding,
        // the issue it belongs to.
        Map<String, List<Integer>> byFingerprint = new LinkedHashMap<>();
        List<String> fingerprints = new ArrayList<>(scanFindings.size());
        for (int index = 0; index < scanFindings.size(); index++) {
            String fingerprint = fingerprintOf(target, scanFindings.get(index));
            fingerprints.add(fingerprint);
            byFingerprint.computeIfAbsent(fingerprint, key -> new ArrayList<>()).add(index);
        }

        // A thousand fingerprints per statement: a scan's findings are sized by the tree it read, and
        // one bind parameter each is refused by the PostgreSQL driver past 65,535 — the scan's ingestion
        // would fail whole. The first row of a fingerprint is kept, as the single statement kept it.
        Map<String, IssueEntity> existing = new LinkedHashMap<>();
        List<String> sought = List.copyOf(byFingerprint.keySet());
        for (int from = 0; from < sought.size(); from += FINGERPRINT_BATCH) {
            issues.findByFingerprintIn(sought.subList(from, Math.min(from + FINGERPRINT_BATCH, sought.size())))
                    .forEach(issue -> existing.putIfAbsent(issue.getFingerprint(), issue));
        }

        List<IssueEntity> created = new ArrayList<>();
        List<IssueEntity> reopened = new ArrayList<>();
        List<IssueEntity> touched = new ArrayList<>(byFingerprint.size());

        for (Map.Entry<String, List<Integer>> entry : byFingerprint.entrySet()) {
            ObservedFinding whole = scanFindings.get(entry.getValue().getFirst());
            IssueEntity issue = existing.get(entry.getKey());
            // Looked up while the identifier is still whole: the advisory text is keyed by it.
            String description = BoundedText.clip(describe(whole, descriptions), BoundedText.TEXT_MAX);
            ObservedFinding finding = fitToColumns(whole);

            if (issue == null) {
                issue = create(scanId, target, entry.getKey(), finding, moment);
                issue.setDescription(description);
                created.add(issue);
            } else {
                if (IssueState.RESOLVED.wireName().equals(issue.getState())) {
                    reopen(issue);
                    reopened.add(issue);
                }
                refresh(issue, finding, scanId, moment);
                if (issue.getDescription() == null) {
                    issue.setDescription(description);
                }
            }
            if (importSource != null) {
                issue.setImportSource(importSource);
            }
            touched.add(issue);
        }

        // Saved before the occurrences are answered: a brand new issue has no identifier yet, and
        // a finding cannot point at nothing.
        List<IssueEntity> saved = issues.saveAll(touched);
        Map<String, Long> idByFingerprint =
                saved.stream().collect(Collectors.toMap(IssueEntity::getFingerprint, IssueEntity::getId, (a, b) -> a));
        List<Long> issueIds = fingerprints.stream().map(idByFingerprint::get).toList();

        // **Once per issue, at its creation.** A leak the next scan sees again is the same leak, and
        // one that comes back after being resolved reopens its issue: neither is announced again.
        // Queued in this transaction, after the save gave each issue its number: a scan that rolls
        // back announces nothing, and the event leaves only once the issues it names exist.
        created.stream().filter(IssueSignals::isLeak).forEach(leak -> events.publishEvent(new SecurityEventRaised(IssueSignals.secretLeak(leak))));

        int resolved = resolveDisappeared(target, scannedTypes, scannedTools, byFingerprint.keySet(), moment);

        SyncResult result = new SyncResult(
                created.size(),
                resolved,
                reopened.size(),
                byFingerprint.size() - created.size() - reopened.size(),
                List.copyOf(created),
                List.copyOf(reopened),
                issueIds);

        if (beforeCommit != null) {
            // **The hook commits with the scan, or neither does.** This was wrapped in a catch that
            // logged "its results are kept", and nothing was kept: the hook queues notifications
            // through `OutboxService.enqueue`, a proxy taking part in this transaction, and an
            // exception leaving it marks the whole transaction rollback-only — the commit then
            // answered `UnexpectedRollbackException` and the dispatcher abandoned the scan as
            // transient (IssueSyncHookDatabaseTest, decision 0033). The catch only hid that. Kept
            // atomic on purpose: a scan whose notifications were lost would announce nothing about
            // what it found, and a retried scan is visible where a missing notification is not.
            beforeCommit.accept(result);
        }

        return result;
    }

    /**
     * Resolves the issues this scan did not see again.
     *
     * <p>Restricted to the types the scan looked at, and to nothing at all when it looked at
     * none — the guard that makes a malformed call harmless rather than destructive.
     *
     * <p><b>A tool-scoped type is never resolved by type</b>, even if a caller names it: only by the
     * tools that actually reported. Resolving {@code plugin} as a type would close every plugin's and
     * every import's issues on the target the first time any one of them came back clean.
     */
    private int resolveDisappeared(
            ScanTarget target, Set<FindingType> scannedTypes, Set<String> scannedTools, Set<String> seen, Instant moment) {
        List<String> types = scannedTypes.stream()
                .filter(type -> !type.toolScoped())
                .map(FindingType::wireName)
                .toList();
        List<String> tools = scannedTools == null ? List.of() : scannedTools.stream()
                .filter(tool -> tool != null && !tool.isBlank())
                .toList();
        if (types.isEmpty() && tools.isEmpty()) {
            return 0;
        }

        List<IssueEntity> open = new ArrayList<>();
        if (!types.isEmpty()) {
            open.addAll(issues.findOpenByTarget(IssueState.OPEN.wireName(), types, repoIdOf(target), containerIdOf(target)));
        }
        if (!tools.isEmpty()) {
            List<String> toolScoped = Arrays.stream(FindingType.values())
                    .filter(FindingType::toolScoped)
                    .map(FindingType::wireName)
                    .toList();
            open.addAll(issues.findOpenByTargetAndTools(
                    IssueState.OPEN.wireName(), toolScoped, tools, repoIdOf(target), containerIdOf(target)));
        }
        List<IssueEntity> disappeared = open.stream()
                .filter(issue -> !seen.contains(issue.getFingerprint()))
                .toList();

        disappeared.forEach(issue -> {
            issue.resolveAt(moment);
        });
        issues.saveAll(disappeared);
        return disappeared.size();
    }

    private IssueEntity create(Long scanId, ScanTarget target, String fingerprint, ObservedFinding finding, Instant moment) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoIdOf(target));
        issue.setContainerId(containerIdOf(target));
        issue.setFingerprint(fingerprint);
        issue.setType(finding.type());
        issue.setIdentifier(finding.identifier());
        issue.setPurl(finding.purl());
        issue.setPackageName(finding.packageName());
        issue.setFilePath(finding.filePath());
        issue.setTool(finding.tool());
        issue.setState(IssueState.OPEN.wireName());
        issue.setFirstSeenAt(moment);
        issue.setLastSeenAt(moment);
        issue.setFirstSeenScanId(scanId);
        issue.setLastSeenScanId(scanId);
        issue.setTimesSeen(1);
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        copyRefreshedFields(issue, finding, true);
        return issue;
    }

    /**
     * What the screen shows under an identifier.
     *
     * <p><b>The lookup alone left every non-vulnerability blank.</b> It is keyed by identifier
     * and holds advisory prose, so a CVE finds its text and a secret asking for
     * {@code generic-api-key} or a Checkov control asking for {@code CKV2_GHA_1} finds nothing —
     * while the scanner had supplied a perfectly good sentence that was written to the finding
     * and then ignored. The backlog showed a rule id and a file path and left the reader to
     * guess: "Detected a Generic API Key" and "Ensure top-level permissions are not set to
     * write-all" existed one table away the whole time.
     *
     * <p>The lookup still wins where it has something: an advisory says more about a CVE than a
     * scanner's one-line summary.
     */
    private static String describe(ObservedFinding finding, Map<String, String> descriptions) {
        String advisory = descriptions.get(orEmpty(finding.identifier()));
        if (advisory != null && !advisory.isBlank()) {
            return advisory;
        }
        String own = finding.description();
        return own == null || own.isBlank() ? null : own;
    }

    private void refresh(IssueEntity issue, ObservedFinding finding, Long scanId, Instant moment) {
        copyRefreshedFields(issue, finding, false);
        issue.setLastSeenAt(moment);
        issue.setLastSeenScanId(scanId);
        issue.setTimesSeen(issue.getTimesSeen() + 1);
        issue.reopen();
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
    private static void copyRefreshedFields(IssueEntity issue, ObservedFinding finding, boolean overwriteNulls) {
        set(finding.packageVersion(), issue::setPackageVersion, overwriteNulls);
        set(finding.line(), issue::setLine, overwriteNulls);
        // Skipped when null like the rest, and for a reason of its own: a container scan does
        // not tell direct from transitive, and must not erase what a repository scan established.
        set(finding.directDependency(), issue::setIsDirectDependency, overwriteNulls);
        set(finding.severity(), issue::setSeverity, overwriteNulls);
        // Refreshed like the rest, and so never erased by a scan that does not carry it: a rule
        // that gains its OWASP declaration passes it on to findings already open, and an agent of
        // an earlier version — which does not send the field — does not take it away.
        set(finding.owaspCategory(), issue::setOwaspCategory, overwriteNulls);
        set(finding.source(), issue::setSource, overwriteNulls);
        set(finding.epssScore(), issue::setEpssScore, overwriteNulls);
        set(finding.cvssScore(), issue::setCvssScore, overwriteNulls);
        set(finding.cvssVector(), issue::setCvssVector, overwriteNulls);
        set(finding.fixState(), issue::setFixState, overwriteNulls);
        set(finding.fixVersions(), issue::setFixVersions, overwriteNulls);
        set(finding.link(), issue::setLink, overwriteNulls);
        // The tool's name and version follow the latest report, like a package's version: a plugin
        // moved to a new image is still one issue, now saying which version saw it last.
        set(finding.toolName(), issue::setToolName, overwriteNulls);
        set(finding.toolVersion(), issue::setToolVersion, overwriteNulls);
        // Both columns are non-nullable, so there is no absent value to skip — but false must
        // not overwrite true on a refresh. Enrichment sets this flag *after* reconciliation, so
        // a second scan arriving before enrichment would otherwise un-flag an exploited
        // vulnerability, and the gate would stop failing on it.
        if (overwriteNulls || finding.kev()) {
            issue.setIsKev(finding.kev());
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

    /**
     * Clips what a scanner reported to the columns the issue stores it in — the finding's own are
     * {@code scanning}'s to clip, at the same widths, when it writes the scan's rows.
     *
     * <p><b>Why here, and only here.</b> Every value below came from a scanner — a purl, a file
     * path, a fix-version list, an advisory link — and one of them past its column failed the flush
     * of the whole scan: every finding of every type lost, the scan marked failed, for one long
     * purl. {@code ComponentInventory} clips its own columns for the same reason. Refusing is not
     * an option for a value nobody here typed.
     *
     * <p><b>After the fingerprint, never before it.</b> The identifier, the purl, the package name
     * and the path are the fingerprint's inputs (AGENTS.md: a data contract), and {@link #sync}
     * computes every fingerprint from the whole values before this runs. Clipping first would give
     * two findings sharing their first 255 characters one identity, and would change the identity
     * of any finding whose value is long — so the stored column is a display copy, and the key is
     * the scanner's own value.
     */
    private static ObservedFinding fitToColumns(ObservedFinding finding) {
        return new ObservedFinding(
                finding.type(),
                finding.source(),
                BoundedText.clip(finding.identifier(), 255),
                BoundedText.clip(finding.severity(), 50),
                BoundedText.clip(finding.packageName(), 255),
                BoundedText.clip(finding.packageVersion(), 255),
                BoundedText.clip(finding.purl(), 255),
                BoundedText.clip(finding.filePath(), 500),
                finding.line(),
                finding.directDependency(),
                finding.owaspCategory(),
                finding.epssScore(),
                finding.cvssScore(),
                BoundedText.clip(finding.cvssVector(), 255),
                BoundedText.clip(finding.fixState(), 50),
                BoundedText.clip(finding.fixVersions(), 255),
                BoundedText.clip(finding.link(), 500),
                finding.kev(),
                BoundedText.clip(finding.description(), BoundedText.TEXT_MAX),
                BoundedText.clip(finding.tool(), 200),
                BoundedText.clip(finding.toolName(), 100),
                BoundedText.clip(finding.toolVersion(), 100));
    }

    private static String fingerprintOf(ScanTarget target, ObservedFinding finding) {
        FindingType type = FindingType.fromWireName(finding.type())
                .orElseThrow(() -> new IllegalStateException(
                        "Unknown finding type \"" + finding.type() + "\": it would fingerprint as itself and "
                                + "never match an existing issue."));

        if (type.toolScoped()) {
            // Rule, normalised path, tool — see IssueFingerprint. A finding of this type without its
            // tool is a defect upstream, and failing here is what keeps it from sharing an identity
            // with every other tool's finding on the same rule and file.
            if (finding.tool() == null || finding.tool().isBlank()) {
                throw new IllegalStateException("A " + type.wireName() + " finding carries no tool key.");
            }
            return IssueFingerprint.ofTool(target, type, finding.tool(), finding.identifier(), finding.filePath());
        }
        return IssueFingerprint.of(new IssueFingerprint.Input(
                target,
                type,
                finding.identifier(),
                finding.purl(),
                finding.packageName(),
                finding.filePath()));
    }

    private static ScanTarget requireTarget(Long scanId, ScanTarget target) {
        return Optional.ofNullable(target)
                .orElseThrow(() -> new IllegalStateException("Scan " + scanId + " belongs to no target."));
    }

    private static Long repoIdOf(ScanTarget target) {
        return target instanceof ScanTarget.Repository repository ? repository.id() : null;
    }

    private static Long containerIdOf(ScanTarget target) {
        return target instanceof ScanTarget.Container container ? container.id() : null;
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }
}

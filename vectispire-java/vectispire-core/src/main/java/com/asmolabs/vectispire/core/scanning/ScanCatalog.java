package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingGraphQueries;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.ExaminingScanRow;
import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import com.asmolabs.vectispire.core.scanning.persistence.queries.PackageImpact;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The scans and their findings as the other modules read them: views and query records, never rows.
 *
 * <p><b>Each method is a query that module ran on the repository itself</b> — the agents' queue
 * figures, the dashboard's recent scans, the exports' document for one scan, the licence and SBOM
 * screens, the compliance evidence, the gate's latest scans. Same query, same parameters, same order;
 * the answer is the {@link ScanView} and {@link ScanFindingView} the scan routes already return,
 * whose components are the entities' property names, so a reader changed {@code getStatus()} for
 * {@code status()} and nothing else (decision 0029). The two projections the queries select into and
 * several readers share — {@link LatestScanRow} and {@link PackageImpact} — are
 * published as they are, read-only, as is {@link ExaminingScanRow}.
 *
 * <p>Row arrays do not cross: a grouped count answers a map, a pair of target columns a {@link
 * ScanOfTarget}.
 */
@Service
@Transactional(readOnly = true)
public class ScanCatalog {

    private final ScanRepository scans;
    private final FindingRepository findings;

    public ScanCatalog(ScanRepository scans, FindingRepository findings) {
        this.scans = scans;
        this.findings = findings;
    }

    /** A scan and the target it is of, without the rest of the row. */
    public record ScanOfTarget(long id, Long repoId, Long containerId) {

        /** A scan attached to neither target is unclassifiable, and left to {@link Visibility#permits}. */
        public ScanTarget target() {
            if (repoId != null) {
                return new ScanTarget.Repository(repoId);
            }
            return containerId == null ? null : new ScanTarget.Container(containerId);
        }
    }

    /** A finding, with the scan it was observed in — what the blast radius walks. */
    public record FindingOnScan(ScanFindingView finding, ScanView scan) {}

    // ------------------------------------------------------------------ scans

    public Optional<ScanView> scan(long id) {
        return scans.findById(id).map(ScanView::of);
    }

    /** Every scan, in the table's order. */
    public List<ScanView> all() {
        return scans.findAll().stream().map(ScanView::of).toList();
    }

    public List<ScanView> ofRepository(long repoId) {
        return scans.findByRepoId(repoId).stream().map(ScanView::of).toList();
    }

    public List<ScanView> ofContainer(long containerId) {
        return scans.findByContainerId(containerId).stream().map(ScanView::of).toList();
    }

    /** Newest first; both targets {@code null} for the whole deployment's. */
    public List<ScanView> history(Long repoId, Long containerId, int limit) {
        return scans.findHistory(repoId, containerId, Limit.of(limit)).stream().map(ScanView::of).toList();
    }

    /**
     * Newest first, of the targets named; either collection may be empty, and both empty is no scan.
     *
     * <p><b>In batches of {@link #LOOKUP_BATCH}, the newest of each kept.</b> The targets are a reader's
     * allowance, sized by the estate: asked in one statement, one bind parameter each, the home page of a
     * reader granted more than 65,535 targets failed on PostgreSQL. The newest {@code limit} scans of a
     * union are among the newest {@code limit} of each of its parts, so asking every batch for its own
     * and keeping the newest of those is the same answer in the same order — the query's, creation
     * instant then identifier, both descending.
     */
    public List<ScanView> recentWithin(Collection<Long> repoIds, Collection<Long> containerIds, int limit) {
        // `in ()` is not valid everywhere, so the other column is asked for an identifier no identity
        // column hands out.
        List<Long> none = List.of(-1L);
        List<ScanEntity> candidates = new java.util.ArrayList<>();
        List<Long> repositories = List.copyOf(java.util.Set.copyOf(repoIds));
        for (int from = 0; from < repositories.size(); from += LOOKUP_BATCH) {
            candidates.addAll(scans.findRecentWithin(
                    repositories.subList(from, Math.min(from + LOOKUP_BATCH, repositories.size())), none, Limit.of(limit)));
        }
        List<Long> images = List.copyOf(java.util.Set.copyOf(containerIds));
        for (int from = 0; from < images.size(); from += LOOKUP_BATCH) {
            candidates.addAll(scans.findRecentWithin(
                    none, images.subList(from, Math.min(from + LOOKUP_BATCH, images.size())), Limit.of(limit)));
        }
        return candidates.stream()
                .sorted(Comparator.comparing(ScanEntity::getCreatedAt, Comparator.reverseOrder())
                        .thenComparing(ScanEntity::getId, Comparator.reverseOrder()))
                .limit(limit)
                .map(ScanView::of)
                .toList();
    }

    /** The identifiers of a target's most recent scans, newest first. */
    public List<Long> recentIds(ScanTarget target, int limit) {
        return switch (target) {
            case ScanTarget.Repository repository -> scans.findRecentIdsByRepoId(repository.id(), Limit.of(limit));
            case ScanTarget.Container container -> scans.findRecentIdsByContainerId(container.id(), Limit.of(limit));
        };
    }

    /**
     * The identifiers of the scans holding an SBOM, newest first, below {@code before}.
     *
     * <p>Which of them the components inventory has indexed is {@code inventory}'s question, over its
     * own table: the statement that answered both at once read {@code inventory}'s rows from here,
     * against the modules' direction.
     */
    public List<Long> idsWithSbomBefore(long before, int limit) {
        return scans.findIdsWithSbomBefore(before, Limit.of(limit));
    }

    /** These scans, newest first; an identifier with no scan is left out. */
    public List<ScanView> scans(Collection<Long> ids) {
        return scans.findAllById(ids).stream()
                .sorted(Comparator.comparing(ScanEntity::getId).reversed())
                .map(ScanView::of)
                .toList();
    }

    public List<LatestScanRow> latestPerRepository() {
        return scans.findLatestPerRepository();
    }

    public List<LatestScanRow> latestPerContainer() {
        return scans.findLatestPerContainer();
    }

    /**
     * Each of these repositories' newest <b>completed</b> scan created at or after {@code since} in
     * which {@code type}'s step produced — the evidence that a repository was examined for it
     * (decision 0032, §6). A repository missing from the answer has no such scan: never scanned for it
     * in that time, every step absent, or only scans from before {@code examined_types}, which nothing
     * recorded — the reader tells those apart with its own questions, and must not read the absence
     * as "examined, and clean".
     *
     * <p><b>A thousand identifiers per statement</b>, as {@code TargetCatalog.carryingCredentials}: a
     * project's repositories are sized by the data, and with one bind parameter each the PostgreSQL
     * driver refuses the statement past 65,535 — as a MySQL server-side statement would.
     *
     * <p><b>Built-in types only.</b> A plugin has three states, kept in {@code plugin_steps}, and an
     * imported tool is its import's row; neither is ever in {@code examined_types}, so asking for one
     * here would answer "never examined" for every repository. Refused instead. A plugin's scope is read
     * from the scans' {@link PluginOutcome}s — {@code produced}, {@code not_applicable}, {@code absent},
     * as {@link ScanView#plugins()} already carries them — by a question of its own beside this one, and
     * an import's from {@code plugins}' import rows; collapsing either into this set would lose the
     * third state (decision 0017).
     *
     * @throws UnsupportedOperationException for a type no built-in step examines — a caller's defect,
     *     never a user's input
     */
    public Map<Long, ExaminingScanRow> newestExamining(Collection<Long> repositoryIds, FindingType type, Instant since) {
        if (!ExaminedTypes.BUILT_IN.contains(type)) {
            throw new UnsupportedOperationException(
                    "No built-in step examines " + type.wireName() + "; its outcomes are not in examined_types.");
        }
        List<Long> distinct = List.copyOf(java.util.Set.copyOf(repositoryIds));
        Map<Long, ExaminingScanRow> newest = new java.util.HashMap<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            scans.findNewestExamining(
                            distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size())),
                            com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED.wireName(),
                            since,
                            ExaminedTypes.pattern(type))
                    .forEach(row -> newest.put(row.repositoryId(), row));
        }
        return Map.copyOf(newest);
    }

    /** How many identifiers one statement binds: far under every engine's limit. */
    static final int LOOKUP_BATCH = 1_000;

    /**
     * A repository's completed scans within an age, and how many of them are from before {@code
     * examined_types} — what tells "every step absent" from "nobody recorded it" when no scan within
     * the age examined a type (decision 0032, §6).
     */
    public record ScansWithin(long repositoryId, long completed, long unrecorded) {}

    /**
     * Each of these repositories' completed scans created at or after {@code since}, counted, the
     * unrecorded among them apart. A repository with none is absent. Batched as {@link #newestExamining}.
     */
    public Map<Long, ScansWithin> completedWithin(Collection<Long> repositoryIds, Instant since) {
        Map<Long, ScansWithin> counted = new java.util.HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            for (Object[] row : scans.countScansWithin(batch,
                    com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED.wireName(), since)) {
                long repository = ((Number) row[0]).longValue();
                counted.put(repository, new ScansWithin(repository, ((Number) row[1]).longValue(),
                        row[2] == null ? 0 : ((Number) row[2]).longValue()));
            }
        }
        return Map.copyOf(counted);
    }

    /** One plugin's outcome in one completed scan of a repository. */
    public record PluginRun(long repositoryId, long scanId, Instant createdAt, PluginOutcome outcome) {}

    /**
     * Each of these repositories' completed scans created at or after {@code since} that name the
     * plugin, with its outcome in each — {@code produced}, {@code not_applicable} or {@code absent},
     * decision 0017's three states kept apart — newest first. A repository whose scans within the age
     * never name the plugin is absent from the answer: they ran without it, which the reader counts as
     * absent (with {@link #completedWithin}), never as clean.
     *
     * <p><b>Read from the scan's own record</b>, {@code plugin_steps}: the plugin's issues say nothing of
     * whether it ran, and {@code examined_types} never holds a tool-scoped type. The statement narrows
     * the rows by the plugin's id in the column's text; the outcome is then read back as {@link
     * ScanView#plugins()} reads it, so a row the text matched by accident — an id inside another
     * field — names no outcome and is left out.
     *
     * @param pluginId a plugin id, lowercase letters, digits and inner hyphens — nothing a {@code like}
     *     pattern reads as a wildcard
     */
    public Map<Long, List<PluginRun>> pluginRunsWithin(Collection<Long> repositoryIds, String pluginId, Instant since) {
        String pattern = pluginPattern(pluginId);
        Map<Long, List<PluginRun>> runs = new java.util.HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            for (Object[] row : scans.findNamingPluginWithin(batch,
                    com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED.wireName(), since, pattern)) {
                long repository = ((Number) row[0]).longValue();
                long scanId = ((Number) row[1]).longValue();
                Instant createdAt = (Instant) row[2];
                PluginOutcome.read((String) row[3]).stream()
                        .filter(outcome -> pluginId.equals(outcome.pluginId()))
                        .findFirst()
                        .ifPresent(outcome -> runs.computeIfAbsent(repository, key -> new java.util.ArrayList<>())
                                .add(new PluginRun(repository, scanId, createdAt, outcome)));
            }
        }
        Map<Long, List<PluginRun>> answer = new java.util.HashMap<>();
        runs.forEach((repository, list) -> answer.put(repository, List.copyOf(list)));
        return Map.copyOf(answer);
    }

    /** Those of these repositories with a completed scan created before {@code before} that names the plugin. */
    public java.util.Set<Long> namingPluginBefore(Collection<Long> repositoryIds, String pluginId, Instant before) {
        String pattern = pluginPattern(pluginId);
        java.util.Set<Long> named = new java.util.HashSet<>();
        for (List<Long> batch : batches(repositoryIds)) {
            named.addAll(scans.findNamingPluginBefore(batch,
                    com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED.wireName(), before, pattern));
        }
        return java.util.Set.copyOf(named);
    }

    /**
     * The languages each of these repositories' newest completed scan found in its tree — what a screen
     * puts beside a plugin's declared languages, in the same vocabulary ({@link DetectedLanguages}).
     *
     * <p><b>A repository missing from the answer is unknown</b>: it has no completed scan, or its newest
     * one recorded no whole census — from before V57, or a census that stopped short. Never an older
     * scan's languages in its place: the newest completed scan is what the repository is now, and a set
     * borrowed from last month would describe a tree that may have changed language since. A present
     * empty set is "counted, and no file named a language". Newest is the highest id, as for the
     * latest-scan rollups; batched as {@link #newestExamining}, a project's repositories being sized by
     * the data.
     */
    public Map<Long, java.util.Set<com.asmolabs.vectispire.common.domain.plugins.Language>> newestDetectedLanguages(
            Collection<Long> repositoryIds) {
        Map<Long, java.util.Set<com.asmolabs.vectispire.common.domain.plugins.Language>> detected = new java.util.HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            for (Object[] row : scans.findNewestDetectedLanguages(batch,
                    com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED.wireName())) {
                long repository = ((Number) row[0]).longValue();
                DetectedLanguages.read((String) row[1]).ifPresent(languages -> detected.put(repository, languages));
            }
        }
        return Map.copyOf(detected);
    }

    /**
     * Each of these targets' newest <b>completed</b> scan, and whether it still holds its SBOM — what a
     * project's consolidated inventory reads (decision 0023). A target missing from the answer has no
     * completed scan. Never an older scan in place of the newest: see {@link NewestCompletedScanRow}.
     *
     * <p>Newest is the highest id, as for the latest-scan rollups; a thousand identifiers per statement,
     * repositories and images each by their own column, since a project's or a solution's targets are
     * sized by the data.
     */
    public Map<ScanTarget, NewestCompletedScanRow> newestCompleted(Collection<ScanTarget> targets) {
        List<Long> repositoryIds = new java.util.ArrayList<>();
        List<Long> containerIds = new java.util.ArrayList<>();
        for (ScanTarget target : targets) {
            switch (target) {
                case ScanTarget.Repository repository -> repositoryIds.add(repository.id());
                case ScanTarget.Container container -> containerIds.add(container.id());
            }
        }
        String completed = com.asmolabs.vectispire.common.domain.scans.ScanStatus.COMPLETED.wireName();
        Map<ScanTarget, NewestCompletedScanRow> newest = new java.util.HashMap<>();
        for (List<Long> batch : batches(repositoryIds)) {
            scans.findNewestWithStatusOfRepositories(batch, completed).forEach(row -> newest.put(row.target(), row));
        }
        for (List<Long> batch : batches(containerIds)) {
            scans.findNewestWithStatusOfContainers(batch, completed).forEach(row -> newest.put(row.target(), row));
        }
        return Map.copyOf(newest);
    }

    /**
     * What one scan recorded of languages: those its census found in the tree, and those the Semgrep
     * rules of its task read. Each is empty where the scan recorded none — unknown, never the empty
     * set (see {@link DetectedLanguages}).
     */
    public record ScanLanguages(Optional<java.util.Set<com.asmolabs.vectispire.common.domain.plugins.Language>> detected,
            Optional<java.util.Set<com.asmolabs.vectispire.common.domain.plugins.Language>> sastRules) {}

    /**
     * Each of these scans' languages, by scan id — what a checklist compares, on the very scan a
     * measurement rests on, to tell a tree its static analysis read from one it did not (decision
     * 0032 §6). A scan that does not exist is absent. A thousand identifiers per statement: the scans
     * of a project's repositories are sized by the data.
     */
    public Map<Long, ScanLanguages> languagesOf(Collection<Long> scanIds) {
        Map<Long, ScanLanguages> languages = new java.util.HashMap<>();
        for (List<Long> batch : batches(scanIds)) {
            for (Object[] row : scans.findLanguagesOf(batch)) {
                languages.put(((Number) row[0]).longValue(), new ScanLanguages(
                        DetectedLanguages.read((String) row[1]), DetectedLanguages.read((String) row[2])));
            }
        }
        return Map.copyOf(languages);
    }

    /**
     * {@code %"pluginId":"<id>"%}, the id closed by its quote so that {@code java} never matches {@code
     * java-arch}. Refused for anything but an id's characters: a {@code %} or {@code _} in it would be a
     * wildcard, and a quote would end the field.
     */
    private static String pluginPattern(String pluginId) {
        if (pluginId == null || pluginId.isEmpty() || !pluginId.chars().allMatch(c -> (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '-')) {
            // A caller's defect, never a user's input: the scope was parsed as a plugin id before it came here.
            throw new UnsupportedOperationException("Not a plugin id: " + pluginId);
        }
        return "%\"pluginId\":\"" + pluginId + "\"%";
    }

    private static List<List<Long>> batches(Collection<Long> repositoryIds) {
        List<Long> distinct = List.copyOf(new java.util.LinkedHashSet<>(repositoryIds));
        List<List<Long>> batches = new java.util.ArrayList<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            batches.add(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size())));
        }
        return batches;
    }

    /** Scans with this status, newest first, as identifier and target only. */
    public List<ScanOfTarget> withStatusNewestFirst(String status) {
        return scans.idsAndTargetsNewestFirst(status).stream()
                .map(row -> new ScanOfTarget(((Number) row[0]).longValue(), asLong(row[1]), asLong(row[2])))
                .toList();
    }

    /** The distinct targets holding a scan with this status, as repository and container columns. */
    public List<ScanOfTarget> targetsWithStatus(String status) {
        return scans.targetsWithStatus(status).stream()
                .map(row -> new ScanOfTarget(0L, asLong(row[0]), asLong(row[1])))
                .toList();
    }

    /** Whether the target holds a scan with this status, ignoring case. */
    public boolean hasScanWithStatus(ScanTarget target, String status) {
        return switch (target) {
            case ScanTarget.Repository repository -> scans.existsByRepoIdAndStatusIgnoreCase(repository.id(), status);
            case ScanTarget.Container container -> scans.existsByContainerIdAndStatusIgnoreCase(container.id(), status);
        };
    }

    /** The target's first scan with this status created after {@code after}, oldest first. */
    public Optional<ScanView> nextWithStatusAfter(ScanTarget target, String status, Instant after) {
        return (switch (target) {
            case ScanTarget.Repository repository ->
                    scans.findFirstByRepoIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(repository.id(), status, after);
            case ScanTarget.Container container ->
                    scans.findFirstByContainerIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(container.id(), status, after);
        }).map(ScanView::of);
    }

    // ------------------------------------------------------------------ the queue's figures

    /** Scans with any of these statuses, oldest first. */
    public List<ScanView> withStatusOldestFirst(Collection<String> statuses) {
        return scans.findByStatusInOrderByCreatedAtAsc(statuses).stream().map(ScanView::of).toList();
    }

    public long countWithStatusSince(String status, Instant after) {
        return scans.countByStatusAndCreatedAtAfter(status, after);
    }

    /** Null when no such scan recorded a duration. */
    public Double averageDurationMsSince(String status, Instant after) {
        return scans.findAvgDurationMsByStatusAndCreatedAtAfter(status, after);
    }

    public long countWithStatusClaimedBy(String status, String claimant) {
        return scans.countByStatusAndClaimedBy(status, claimant);
    }

    /** Scans with this status per required label — the label {@code null} when none is — in query order. */
    public Map<String, Long> countByRequiredLabel(String status) {
        return grouped(scans.countPendingByRequiredLabel(status));
    }

    /** A waiting scan of a repository that was counted at least one attempt. */
    public record AttemptedScan(long id, long repoId) {}

    /** The waiting scans of repositories that were counted at least one attempt. */
    public List<AttemptedScan> waitingWithAttempts() {
        return scans.findAttemptedRepositoryScans(com.asmolabs.vectispire.common.domain.scans.ScanStatus.PENDING.wireName())
                .stream()
                .map(row -> new AttemptedScan(((Number) row[0]).longValue(), ((Number) row[1]).longValue()))
                .toList();
    }

    /**
     * Gives these waiting scans their attempts back — <b>the catalog's one write</b>, on {@code agents}'
     * behalf, as {@code TargetCatalog} writes a column another module decides: the claims that counted
     * the attempts were the agents' protocol's, and so is knowing they never delivered anything.
     * A scan claimed since it was read is left as it is.
     *
     * @return how many scans were changed
     */
    @Transactional
    public int refundAttempts(Collection<Long> ids) {
        List<Long> distinct = List.copyOf(java.util.Set.copyOf(ids));
        int changed = 0;
        for (int from = 0; from < distinct.size(); from += 1_000) {
            changed += scans.resetAttempts(
                    distinct.subList(from, Math.min(from + 1_000, distinct.size())),
                    com.asmolabs.vectispire.common.domain.scans.ScanStatus.PENDING.wireName());
        }
        return changed;
    }

    /** Waiting scans of one repository that require one label — {@code null} when they require none. */
    public record WaitingScans(String requiredLabel, long repoId, long scans) {}

    /** The waiting scans of repositories, per required label and repository. */
    public List<WaitingScans> waitingRepositories() {
        return scans.countPendingByRequiredLabelAndRepository(
                        com.asmolabs.vectispire.common.domain.scans.ScanStatus.PENDING.wireName())
                .stream()
                .map(row -> new WaitingScans(
                        (String) row[0], ((Number) row[1]).longValue(), ((Number) row[2]).longValue()))
                .toList();
    }

    /** Scans with this status per claimant, in query order. */
    public Map<String, Long> countByClaimant(String status) {
        return grouped(scans.countRunningByClaimant(status));
    }

    // ------------------------------------------------------------------ findings

    public List<ScanFindingView> findings(long scanId) {
        return findings.findByScanId(scanId).stream().map(ScanFindingView::of).toList();
    }

    /** The findings of these scans, in one query — the triage history reads a page of scans at once. */
    public List<ScanFindingView> findingsOfScans(Collection<Long> scanIds) {
        return scanIds.isEmpty()
                ? List.of()
                : findings.findByScanIdIn(scanIds).stream().map(ScanFindingView::of).toList();
    }

    /** Where one issue was observed, newest scan first: the sightings of its detail. */
    public List<FindingOnScan> sightings(long issueId, int limit) {
        return findings.sightingsOf(issueId, Limit.of(limit)).stream()
                .map(row -> new FindingOnScan(
                        ScanFindingView.of((FindingEntity) row[0]), ScanView.of((ScanEntity) row[1])))
                .toList();
    }

    /**
     * The licence findings of these scans, {@link #LOOKUP_BATCH} scans per statement: the portfolio's
     * licence inventory asks for every scan of the estate, and one bind parameter each is refused by the
     * PostgreSQL driver past 65,535.
     */
    public List<ScanFindingView> licenseFindings(Collection<Long> scanIds) {
        List<Long> distinct = List.copyOf(java.util.Set.copyOf(scanIds));
        List<ScanFindingView> found = new java.util.ArrayList<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            findings.findLicenseFindings(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size())))
                    .forEach(row -> found.add(ScanFindingView.of(row)));
        }
        return found;
    }

    public long countFindings(long scanId, String severity) {
        return findings.countByScanIdAndSeverity(scanId, severity);
    }

    public long countKevFindings(long scanId) {
        return findings.countByScanIdAndIsKevTrue(scanId);
    }

    public long countFindingsOfType(long scanId, String type) {
        return findings.countByScanIdAndType(scanId, type);
    }

    /** See {@link FindingGraphQueries#forGraph}: narrowed by visibility in the query itself. */
    public List<FindingOnScan> findingsForGraph(String query, boolean cveQuery, boolean excludeSecrets, Visibility allowed) {
        return findings.forGraph(query, cveQuery, excludeSecrets, allowed).stream()
                .map(row -> new FindingOnScan(ScanFindingView.of(row.finding()), ScanView.of(row.scan())))
                .toList();
    }

    /** See {@link FindingGraphQueries#packageImpacts}. */
    public List<PackageImpact> packageImpacts(Visibility allowed) {
        return findings.packageImpacts(allowed);
    }

    private static Map<String, Long> grouped(List<Object[]> rows) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Object[] row : rows) {
            counts.put((String) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    private static Long asLong(Object value) {
        return value == null ? null : ((Number) value).longValue();
    }
}

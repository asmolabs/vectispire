package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.gate.GateIssue;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.persistence.IssueAggregateQueries;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueSpecifications;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The issues as the other modules read them: views, query records and counts, never rows.
 *
 * <p><b>Each method is a query a module ran on the repository itself</b> — the posture figures, the
 * compliance evidence, the exports, the gate, the ticket sweep, the threat-intel feed, the AI advisor,
 * the rule sets' impact. Same query, same parameters, same order. Where a module passed a JPA
 * specification it passes {@link IssueFilters} now, the criteria the specification was built from —
 * the visibility among them — and {@code IssueSpecifications} builds the one predicate. Rows come back
 * as {@link IssueView}, whose components are the entity's property names, or as the projections of
 * {@code IssueRows} and {@code IssueAggregates}, published as they are (decision 0029).
 *
 * <p><b>Two writes, each on behalf of the module that decides them</b>: the ticket a sweep opened,
 * and the exploitation figures the threat-intel feed re-evaluated. The issue's row is written here,
 * by its owner, with the value the other module decided.
 */
@Service
@Transactional(readOnly = true)
public class IssueCatalog {

    /** Issues per flag update, and repositories per grouped count, under every engine's bind-parameter ceiling. */
    private static final int FLAG_BATCH = 1_000;

    private final IssueRepository issues;

    public IssueCatalog(IssueRepository issues) {
        this.issues = issues;
    }

    /** A count of rows grouped by one key: a rule, a file, an identifier. */
    public record KeyCount(String key, long count) {}

    /** A count of rows grouped by repository. */
    public record RepositoryCount(Long repositoryId, long count) {}

    /** Open issues per target, severity, type and exploitation — the compliance table's breakdown. */
    public record TargetBreakdown(Long repoId, Long containerId, String severity, String type, boolean kev, long count) {}

    /**
     * Whether the KEV catalogue lists one issue's CVE, as the threat-intel feed decided.
     *
     * <p>The flag alone. It carried the EPSS score too, read at the start of the catalogue's
     * transaction and written back at its end — which would put back a score the EPSS feed had
     * refreshed in between; each feed writes its own column now ({@link #recordEpss}).
     */
    public record Exploitation(long issueId, boolean kev) {}

    // ------------------------------------------------------------------ by criteria

    public long count(IssueFilters filters) {
        return issues.count(IssueSpecifications.of(filters));
    }

    /** Every issue the criteria select, as the backlog's view. */
    public List<IssueView> issues(IssueFilters filters) {
        return issues.findAll(IssueSpecifications.of(filters)).stream().map(IssueView::of).toList();
    }

    /** The first {@code max} issues the criteria select, in the repository's order. */
    public List<IssueView> issues(IssueFilters filters, int max) {
        return issues.findAll(IssueSpecifications.of(filters), PageRequest.ofSize(max)).stream()
                .map(IssueView::of)
                .toList();
    }

    /**
     * The criteria's rows as one of the {@code IssueRows} projections — only the columns it names are
     * read, which is what each projection exists for.
     */
    public <R> List<R> rows(IssueFilters filters, Class<R> shape) {
        return issues.findBy(IssueSpecifications.of(filters), query -> query.as(shape).all());
    }

    /**
     * The criteria's issues that carry a triage decision, serialized with the caller's mapper — the
     * evidence bundle's triage file, byte for byte what it serialized from the rows themselves.
     *
     * <p>Serialized here rather than handed over as views: the file is a record auditors keep, and its
     * shape is the row's as Jackson reads it. A view would be a second shape of the same file.
     */
    public byte[] triagedAsJson(IssueFilters filters, ObjectMapper json) throws JsonProcessingException {
        List<IssueEntity> triaged = issues.findAll(IssueSpecifications.of(filters)).stream()
                .filter(issue -> issue.getTriageStatus() != null && !issue.getTriageStatus().equals("untriaged"))
                .toList();
        return json.writeValueAsBytes(triaged);
    }

    // ------------------------------------------------------------------ aggregates

    public List<IssueAggregates.SeverityTypeCount> countGroupedBySeverityAndType(IssueFilters filters) {
        return issues.countGroupedBySeverityAndType(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.TargetSeverityCount> countOpenByTargetAndSeverity(IssueFilters filters) {
        return issues.countOpenByTargetAndSeverity(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.TargetResolutions> countResolvedByTarget(IssueFilters filters) {
        return issues.countResolvedByTarget(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.ResolvedDuration> resolvedDurationsSince(IssueFilters filters, Instant since) {
        return issues.resolvedDurationsSince(IssueSpecifications.of(filters), since);
    }

    public List<IssueAggregates.OpenBacklog> openBacklogBySeverity(IssueFilters filters) {
        return issues.openBacklogBySeverity(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.TypePackaging> countOpenByTypeAndPackaging(IssueFilters filters) {
        return issues.countOpenByTypeAndPackaging(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.OwaspCategoryCount> countOpenSastByOwaspCategory(IssueFilters filters) {
        return issues.countOpenSastByOwaspCategory(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.PackageWeight> weighPackages(IssueFilters filters) {
        return issues.weighPackages(IssueSpecifications.of(filters));
    }

    public List<IssueAggregates.PackageDetail> detailPackages(IssueFilters filters, Collection<String> packageNames) {
        return issues.detailPackages(IssueSpecifications.of(filters), packageNames);
    }

    /**
     * See {@code IssueRepository.countOpenGroupedByTarget}.
     *
     * <p><b>Tolerant of a numeric flag, though no engine currently sends one.</b> Written on the
     * assumption that SQLite would hand back an Integer where the others hand back a Boolean.
     * Measured afterwards, and that is not what happens: the projection selects a mapped entity
     * attribute, so Hibernate normalises it to {@code Boolean} on every engine the campaign runs —
     * a plain cast would pass everywhere. Kept anyway, and the reason is narrow rather than
     * superstitious: the day this projection reads a column the entity does not map, the
     * normalisation goes with it. (It was {@code ComplianceService.toBoolean}; the row arrays stay in
     * this module now.)
     */
    public List<TargetBreakdown> countOpenGroupedByTarget(String state, Collection<String> settled) {
        return issues.countOpenGroupedByTarget(state, settled).stream()
                .map(row -> new TargetBreakdown(
                        (Long) row[0],
                        (Long) row[1],
                        (String) row[2],
                        (String) row[3],
                        row[4] instanceof Boolean flag ? flag : row[4] instanceof Number n && n.intValue() != 0,
                        ((Number) row[5]).longValue()))
                .toList();
    }

    /** Open issues of one type per identifier, in query order. */
    public Map<String, Long> countOpenByIdentifier(String state, String type) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Object[] row : issues.countOpenByIdentifier(state, type)) {
            counts.put((String) row[0], ((Number) row[1]).longValue());
        }
        return counts;
    }

    // ------------------------------------------------------------------ the quality screen's counts

    public long countByStateAndType(String state, String type) {
        return issues.countByStateAndType(state, type);
    }

    public long countDistinctRules(String state, String type) {
        return issues.countDistinctRules(state, type);
    }

    public long countDistinctFiles(String state, String type) {
        return issues.countDistinctFiles(state, type);
    }

    public List<KeyCount> countOpenByRule(String state, String type, int limit) {
        return keyed(issues.countOpenByRule(state, type, Limit.of(limit)));
    }

    public List<KeyCount> countOpenByFile(String state, String type, int limit) {
        return keyed(issues.countOpenByFile(state, type, Limit.of(limit)));
    }

    public List<RepositoryCount> countOpenByTargetRepository(String state, String type, int limit) {
        return byRepository(issues.countOpenByTargetRepository(state, type, Limit.of(limit)));
    }

    public long countByStateAndTypeWithin(String state, String type, Collection<Long> repoIds) {
        return issues.count(within(state, type, repoIds));
    }

    public long countDistinctRulesWithin(String state, String type, Collection<Long> repoIds) {
        return issues.countDistinct(within(state, type, repoIds), IssueAggregateQueries.Axis.RULE);
    }

    public long countDistinctFilesWithin(String state, String type, Collection<Long> repoIds) {
        return issues.countDistinct(within(state, type, repoIds), IssueAggregateQueries.Axis.FILE);
    }

    public List<KeyCount> countOpenByRuleWithin(String state, String type, Collection<Long> repoIds, int limit) {
        return keyed(issues.countGrouped(within(state, type, repoIds), IssueAggregateQueries.Axis.RULE, limit));
    }

    public List<KeyCount> countOpenByFileWithin(String state, String type, Collection<Long> repoIds, int limit) {
        return keyed(issues.countGrouped(within(state, type, repoIds), IssueAggregateQueries.Axis.FILE, limit));
    }

    public List<RepositoryCount> countOpenByTargetRepositoryWithin(
            String state, String type, Collection<Long> repoIds, int limit) {
        return byRepository(issues.countGrouped(
                within(state, type, repoIds), IssueAggregateQueries.Axis.REPOSITORY, limit));
    }

    /**
     * One state and one type of these repositories' issues — the narrowing the quality overview asks
     * with a reader's repositories, which are sized by the estate: through {@link IssueFilters#within},
     * written into the statement rather than bound, never failing past the driver's parameter ceiling.
     * An empty collection matches nothing.
     */
    private static org.springframework.data.jpa.domain.Specification<IssueEntity> within(
            String state, String type, Collection<Long> repoIds) {
        return IssueSpecifications.of(new IssueFilters(
                        state, null, type, null, null, null, false, false, null,
                        com.asmolabs.vectispire.common.domain.access.Visibility.everything())
                .within(repoIds.stream().map(ScanTarget.Repository::new).toList()));
    }

    /** Issues of one repository, severity and state in one scope — the rows a checklist's figures add up. */
    public record ScopeCount(long repositoryId, String severity, String state, long count) {}

    /**
     * These repositories' issues of one built-in type, per repository, severity and state, settled
     * triage left out — a triage status this version does not know is counted (decision 0032 §6). The
     * resolved ones are counted too: a resolved ratio needs both sides. Every state is answered as
     * stored, and the reader counts one it does not know as open.
     *
     * <p><b>A thousand identifiers per statement</b>: a project's repositories are sized by the data,
     * and the PostgreSQL driver refuses a statement past 65,535 bind parameters.
     */
    public List<ScopeCount> countUnsettledOfTypeWithin(String type, Collection<Long> repoIds) {
        return scopeCounts(repoIds, batch -> issues.countUnsettledOfTypeWithin(batch, type,
                com.asmolabs.vectispire.common.domain.issues.TriageStatus.settledWireNames()));
    }

    /** The same, for one tool's issues, by the fingerprint's tool key: {@code plugin:<id>}, {@code import:<source>/<tool>}. */
    public List<ScopeCount> countUnsettledOfToolWithin(String toolKey, Collection<Long> repoIds) {
        return scopeCounts(repoIds, batch -> issues.countUnsettledOfToolWithin(batch, toolKey,
                com.asmolabs.vectispire.common.domain.issues.TriageStatus.settledWireNames()));
    }

    private static List<ScopeCount> scopeCounts(Collection<Long> repoIds,
            java.util.function.Function<List<Long>, List<Object[]>> query) {
        List<Long> distinct = List.copyOf(new java.util.LinkedHashSet<>(repoIds));
        List<ScopeCount> counts = new ArrayList<>();
        for (int from = 0; from < distinct.size(); from += FLAG_BATCH) {
            for (Object[] row : query.apply(distinct.subList(from, Math.min(from + FLAG_BATCH, distinct.size())))) {
                counts.add(new ScopeCount(((Number) row[0]).longValue(), (String) row[1], (String) row[2],
                        ((Number) row[3]).longValue()));
            }
        }
        return List.copyOf(counts);
    }

    // ------------------------------------------------------------------ one target, one issue

    public Optional<IssueView> issue(long id) {
        return issues.findById(id).map(IssueView::of);
    }

    public List<IssueView> withIdentifier(String identifier) {
        return issues.findByIdentifier(identifier).stream().map(IssueView::of).toList();
    }

    public long countByStateAndRepository(String state, long repoId) {
        return issues.countByStateAndRepository(state, repoId);
    }

    public List<IssueView> ofRepositoryInState(long repoId, String state) {
        return issues.findByRepositoryAndState(repoId, state).stream().map(IssueView::of).toList();
    }

    /** One projection of a repository's issues in a state, settled triage left out. */
    public <R> List<R> unsettledOfRepository(long repoId, String state, Collection<String> settled, Class<R> shape) {
        return issues.findUnsettledByRepositoryAndState(repoId, state, settled, shape);
    }

    /**
     * The same projection for several repositories at once, settled triage left out — a thousand
     * repositories per statement, since the attack-path overview hands every repository the
     * reader may see, and one bind parameter each fails on PostgreSQL past 65,535.
     */
    public <R> List<R> unsettledOfRepositories(
            String state, Collection<Long> repoIds, Collection<String> settled, Class<R> shape) {
        List<Long> distinct = List.copyOf(new java.util.LinkedHashSet<>(repoIds));
        List<R> rows = new ArrayList<>();
        for (int from = 0; from < distinct.size(); from += FLAG_BATCH) {
            rows.addAll(issues.findByStateAndRepoIdInAndTriageStatusNotIn(
                    state, distinct.subList(from, Math.min(from + FLAG_BATCH, distinct.size())), settled, shape));
        }
        return rows;
    }

    /** The open issues of one target, as the gate weighs them. */
    public List<GateIssue> gateIssuesOf(ScanTarget target, String state) {
        List<IssueEntity> rows = switch (target) {
            case ScanTarget.Repository repository -> issues.findByStateAndRepoId(state, repository.id());
            case ScanTarget.Container container -> issues.findByStateAndRepoIdIsNullAndContainerId(state, container.id());
        };
        return rows.stream().map(IssueViews::forGate).toList();
    }

    /** Every issue in a state, as one projection. */
    public <R> List<R> inState(String state, Class<R> shape) {
        return issues.findByState(state, shape);
    }

    // ------------------------------------------------------------------ tickets

    /** See {@code IssueRepository.findActionableWithoutTicket}: worst first, at most {@code limit}. */
    public List<IssueView> actionableWithoutTicket(String state, Collection<String> excluded, int limit) {
        return issues.findActionableWithoutTicket(state, excluded, Limit.of(limit)).stream()
                .map(IssueView::of)
                .toList();
    }

    /** Resolved issues whose ticket is still open, at most {@code limit}. */
    public List<IssueView> resolvedWithOpenTicket(int limit) {
        return issues.findResolvedWithOpenTicket(Limit.of(limit)).stream().map(IssueView::of).toList();
    }

    public Optional<IssueView> withTicket(String reference) {
        return issues.findByTicketRefOrIid(reference).map(IssueView::of);
    }

    /** Records the ticket a sweep opened — or closed — for an issue: {@code tickets}' decision. */
    @Transactional
    public int attachTicket(long issueId, String reference, String url) {
        return issues.attachTicket(issueId, reference, url);
    }

    // ------------------------------------------------------------------ threat intelligence

    /**
     * Writes the exploitation flags the feed re-evaluated — {@code threatintel}'s decision — onto the
     * issues, in the feed's transaction: the flag and nothing else, a thousand issues a statement.
     *
     * <p><b>Not the rows saved whole.</b> The feed reads the open issues at the start of its
     * transaction and wrote them back at its end, every column as it had read them: an EPSS score the
     * EPSS refresh committed in between, or a scan's {@code lastSeenAt}, was put back to its old value.
     * And the lookup of every flagged row was one {@code in} list, which the engines bound.
     */
    @Transactional
    public void recordExploitation(Collection<Exploitation> updates) {
        Map<Boolean, List<Long>> byFlag = new LinkedHashMap<>();
        updates.forEach(update -> byFlag.computeIfAbsent(update.kev(), flag -> new ArrayList<>()).add(update.issueId()));
        byFlag.forEach((kev, ids) -> {
            for (int from = 0; from < ids.size(); from += FLAG_BATCH) {
                issues.setKev(ids.subList(from, Math.min(from + FLAG_BATCH, ids.size())), kev);
            }
        });
    }

    /**
     * A page of the open issues that name an identifier, in id order after {@code afterId} — the EPSS
     * refresh and the KEV re-evaluation walk the backlog with these, a bounded page per transaction,
     * rather than reading every open issue at once.
     *
     * @param shape {@link IssueRows.EpssCandidate} or {@link IssueRows.KevCandidate}: what the walk reads
     */
    public <R> List<R> openIdentifiedAfter(long afterId, Collection<String> closedStates, int limit, Class<R> shape) {
        return issues.findByIdGreaterThanAndStateNotInAndIdentifierIsNotNullOrderByIdAsc(
                afterId, closedStates, Limit.of(limit), shape);
    }

    /**
     * Writes the EPSS scores the feed decided — {@code threatintel}'s decision — onto these issues, in
     * one transaction of its own, one update per distinct score — the issues of one CVE across the
     * estate share one. A targeted update rather than rows saved whole: a scan refreshing the same
     * issue meanwhile would otherwise lose its {@code lastSeenAt} and its count to a row read before
     * it.
     */
    @Transactional
    public int recordEpss(Map<Long, Double> scores) {
        if (scores.isEmpty()) {
            return 0;
        }
        Map<Double, List<Long>> byScore = new LinkedHashMap<>();
        scores.forEach((id, score) -> byScore.computeIfAbsent(score, key -> new ArrayList<>()).add(id));
        int updated = 0;
        for (Map.Entry<Double, List<Long>> group : byScore.entrySet()) {
            updated += issues.setEpssScore(group.getValue(), group.getKey());
        }
        return updated;
    }

    private static List<KeyCount> keyed(List<Object[]> rows) {
        return rows.stream().map(row -> new KeyCount((String) row[0], ((Number) row[1]).longValue())).toList();
    }

    private static List<RepositoryCount> byRepository(List<Object[]> rows) {
        return rows.stream()
                .map(row -> new RepositoryCount(((Number) row[0]).longValue(), ((Number) row[1]).longValue()))
                .toList();
    }
}

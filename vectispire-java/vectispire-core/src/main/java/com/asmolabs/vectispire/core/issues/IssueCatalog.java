package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.gate.GateIssue;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.internal.IssueSpecifications;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.Issues;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
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

    private final Issues issues;

    public IssueCatalog(Issues issues) {
        this.issues = issues;
    }

    /** A count of rows grouped by one key: a rule, a file, an identifier. */
    public record KeyCount(String key, long count) {}

    /** A count of rows grouped by repository. */
    public record RepositoryCount(Long repositoryId, long count) {}

    /** Open issues per target, severity, type and exploitation — the compliance table's breakdown. */
    public record TargetBreakdown(Long repoId, Long containerId, String severity, String type, boolean kev, long count) {}

    /** The exploitation figures the threat-intel feed decided for one issue. */
    public record Exploitation(long issueId, boolean kev, Double epssScore) {}

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
     * See {@code Issues.countOpenGroupedByTarget}.
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
        return issues.countByStateAndTypeWithin(state, type, repoIds);
    }

    public long countDistinctRulesWithin(String state, String type, Collection<Long> repoIds) {
        return issues.countDistinctRulesWithin(state, type, repoIds);
    }

    public long countDistinctFilesWithin(String state, String type, Collection<Long> repoIds) {
        return issues.countDistinctFilesWithin(state, type, repoIds);
    }

    public List<KeyCount> countOpenByRuleWithin(String state, String type, Collection<Long> repoIds, int limit) {
        return keyed(issues.countOpenByRuleWithin(state, type, repoIds, Limit.of(limit)));
    }

    public List<KeyCount> countOpenByFileWithin(String state, String type, Collection<Long> repoIds, int limit) {
        return keyed(issues.countOpenByFileWithin(state, type, repoIds, Limit.of(limit)));
    }

    public List<RepositoryCount> countOpenByTargetRepositoryWithin(
            String state, String type, Collection<Long> repoIds, int limit) {
        return byRepository(issues.countOpenByTargetRepositoryWithin(state, type, repoIds, Limit.of(limit)));
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

    /** The same projection for several repositories at once, settled triage left out. */
    public <R> List<R> unsettledOfRepositories(
            String state, Collection<Long> repoIds, Collection<String> settled, Class<R> shape) {
        return issues.findByStateAndRepoIdInAndTriageStatusNotIn(state, repoIds, settled, shape);
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

    /** Every issue in none of these states. */
    public List<IssueView> notInStates(Collection<String> states) {
        return issues.findByStateNotIn(states).stream().map(IssueView::of).toList();
    }

    // ------------------------------------------------------------------ tickets

    /** See {@code Issues.findActionableWithoutTicket}: worst first, at most {@code limit}. */
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
     * Writes the exploitation figures the feed re-evaluated — {@code threatintel}'s decision — onto the
     * issues, in the feed's transaction: one read of the rows named, one batch write.
     */
    @Transactional
    public void recordExploitation(Collection<Exploitation> updates) {
        if (updates.isEmpty()) {
            return;
        }
        Map<Long, Exploitation> byIssue = new LinkedHashMap<>();
        updates.forEach(update -> byIssue.put(update.issueId(), update));
        List<IssueEntity> rows = issues.findAllById(byIssue.keySet());
        rows.forEach(row -> {
            Exploitation update = byIssue.get(row.getId());
            row.setKev(update.kev());
            row.setEpssScore(update.epssScore());
        });
        issues.saveAll(rows);
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

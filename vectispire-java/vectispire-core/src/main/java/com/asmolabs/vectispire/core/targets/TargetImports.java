package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.core.access.TargetGrants;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.ProjectView;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.SolutionView;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What decision 0037's import from a forge asks of the targets' owner: which repositories are already targets,
 * which solutions and projects exist by name, how far a project's grants reach — and the creations themselves,
 * many in one transaction.
 *
 * <p><b>The existing gestures, in a loop.</b> A target is created by {@link RepositoryAdministrationService}, a
 * solution and a project by {@link SolutionAdministrationService}: the same refusals as the forms — a credential
 * in a URL, a host off the allow-list, an HTTPS token presented to another host, a name taken — and the same
 * entries. An import is not a second way to create a target.
 *
 * <p><b>One transaction, and the entries after it.</b> An import creates everything or nothing (§5): a failure
 * halfway leaves no half-filed estate to clean up by hand. The forms audit each write straight after its own
 * commit; here there is one commit, so the entries are collected while the batch runs and recorded once it has
 * committed — recorded inside it, they would describe writes that may still roll back, and of a batch that rolled
 * back none is recorded. Only {@link #inOneTransaction} reaches the services' batch forms, which are
 * package-private for that reason: there is no public body that writes without its entry.
 *
 * <p><b>Who sees the new targets is not changed here.</b> No grant is written (answer 5): a target is visible to
 * administrators, and to whoever holds a grant on the project it is filed into, which {@link #grantees} counts for
 * the preview.
 */
@Service
public class TargetImports {

    /** How many identities one lookup binds: far under every engine's limit. */
    static final int LOOKUP_BATCH = 1_000;

    private final RepositoryAdministrationService repositories;
    private final SolutionAdministrationService solutions;
    private final GitRepositoryRepository rows;
    private final TargetScans scans;
    private final TargetGrants grants;
    private final VisibilityService visibility;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;

    public TargetImports(
            RepositoryAdministrationService repositories,
            SolutionAdministrationService solutions,
            GitRepositoryRepository rows,
            TargetScans scans,
            TargetGrants grants,
            VisibilityService visibility,
            AuditLogService audit,
            PlatformTransactionManager transactions) {
        this.repositories = repositories;
        this.solutions = solutions;
        this.rows = rows;
        this.scans = scans;
        this.grants = grants;
        this.visibility = visibility;
        this.audit = audit;
        this.transactions = new TransactionTemplate(transactions);
    }

    /**
     * How far a project's grants reach: the accounts granted it directly and the teams granted it, each team's
     * members seeing it through the team.
     */
    public record ProjectReach(long accounts, long teams) {}

    /**
     * The targets filing each of these repositories, whatever their branch and sub-path — the identity rule of
     * {@link RepositoryUrl#identity}, which the repository form's duplicate refusal brought (V73) and the import
     * reuses rather than writing a second one. An identity no target files is missing from the answer.
     *
     * <p>Read from the stored {@code url_identity}, in batches, and for the rows the keying has not reached yet
     * from their URL — the same method, so that a target added by an instance of the previous version is found
     * all the same.
     */
    public Map<String, List<Long>> presentByIdentity(Collection<String> identities) {
        List<String> wanted = identities.stream().distinct().toList();
        Map<String, List<Long>> present = new HashMap<>();
        for (int from = 0; from < wanted.size(); from += LOOKUP_BATCH) {
            for (Object[] row : rows.findIdsByUrlIdentityIn(wanted.subList(from, Math.min(from + LOOKUP_BATCH, wanted.size())))) {
                present.computeIfAbsent((String) row[1], ignored -> new ArrayList<>()).add(((Number) row[0]).longValue());
            }
        }
        java.util.Set<String> asked = new java.util.HashSet<>(wanted);
        for (Object[] row : rows.findUnidentified()) {
            RepositoryUrl.identity((String) row[1]).filter(asked::contains).ifPresent(identity ->
                    present.computeIfAbsent(identity, ignored -> new ArrayList<>()).add(((Number) row[0]).longValue()));
        }
        present.values().forEach(ids -> ids.sort(Long::compare));
        return present;
    }

    /** The solution of that name, case aside — reused by an import rather than created twice. */
    public Optional<SolutionView> solutionNamed(String name) {
        return solutions.solutionNamed(name);
    }

    /** The project of that name in the solution, case aside — reused by an import rather than created twice. */
    public Optional<ProjectView> projectNamed(long solutionId, String name) {
        return solutions.projectNamed(solutionId, name);
    }

    /** The reach of each of these projects that some grant names; a project missing from the answer has none. */
    public Map<Long, ProjectReach> grantees(Collection<Long> projectIds) {
        Map<Long, ProjectReach> reach = new HashMap<>();
        grants.granteesOfProjects(projectIds).forEach((id, granted) ->
                reach.put(id, new ProjectReach(granted.accounts(), granted.teams())));
        return reach;
    }

    /** Whether every signed-in account sees every target, or only what it was granted. */
    public VisibilityMode visibilityMode() {
        return visibility.mode();
    }

    /** Why the repository form would refuse these changes, without writing: empty when it would accept them. */
    public Optional<String> refusal(RepositoryAdministrationService.Changes changes) {
        return repositories.refusal(changes);
    }

    /**
     * Runs {@code work} in one transaction, then records the entries of what it created — none if it rolled back.
     *
     * @param actor the person importing, named by every entry
     */
    public <T> T inOneTransaction(RequestActor actor, Function<Batch, T> work) {
        List<AuditLogService.Record> entries = new ArrayList<>();
        T result = transactions.execute(status -> work.apply(new Batch(actor, entries)));
        entries.forEach(audit::record);
        return result;
    }

    /** The creations an import makes, inside {@link #inOneTransaction}. */
    public final class Batch {

        private final RequestActor actor;
        private final List<AuditLogService.Record> entries;

        private Batch(RequestActor actor, List<AuditLogService.Record> entries) {
            this.actor = actor;
            this.entries = entries;
        }

        /** The solution of that name, created when none exists — reused, never renamed. */
        public Placed<SolutionView> solution(String name) {
            return solutions.solutionNamed(name)
                    .map(existing -> new Placed<>(existing, false))
                    .orElseGet(() -> new Placed<>(solutions.createSolution(name, null, actor, entries), true));
        }

        /** The project of that name in the solution, created when none exists — reused, never moved. */
        public Placed<ProjectView> project(long solutionId, String name) {
            return solutions.projectNamed(solutionId, name)
                    .map(existing -> new Placed<>(existing, false))
                    .orElseGet(() -> new Placed<>(solutions.createProject(solutionId, name, null, actor, entries), true));
        }

        /**
         * A repository target, as the form creates it, filed into {@code projectId} at its creation.
         *
         * @param scheduledFrom its first default round is its own slot after this instant — see {@link
         *     RepositoryAdministrationService#createImported}
         * @param provenance appended to its entry
         */
        public RepositoryView repository(RepositoryAdministrationService.Changes changes, Long projectId,
                Instant scheduledFrom, String provenance) {
            return repositories.createImported(changes, projectId, scheduledFrom, provenance, actor, entries);
        }

        /** Its first scan, claimed by no executor before {@code notBefore}. */
        public TargetScans.Queued firstScan(RepositoryView repository, Instant notBefore) {
            return scans.queue(repository, notBefore);
        }
    }

    /** A solution or project an import files into, and whether the import created it. */
    public record Placed<T>(T view, boolean created) {}
}

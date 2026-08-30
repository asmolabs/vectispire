package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.gate.GateIssue;
import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.gate.GateVerdict;
import com.asmolabs.vectispire.common.domain.gate.PolicyGate;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.PolicyLookup;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.ResolvedPolicy;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.Scope;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.StoredPolicy;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.GatePolicyEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueRows;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GatePolicies;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The verdict a pipeline asks for, and the posture the security screen shows.
 *
 * <p><b>Both go through the same {@link PolicyGate#evaluate}.</b> That is the property that
 * makes the screen trustworthy: a SQL aggregation recounting "issues above the threshold" would
 * agree today and diverge at the first flag added to the policy — and nobody would see it until
 * a pipeline and a screen contradicted each other about the same repository.
 */
@Service
public class GateService {

    private static final String SCOPE_GLOBAL = "global";

    /** What a global policy stores in a column the schema declares not-null. */
    private static final long NO_TARGET = 0L;

    private final Issues issues;
    private final GatePolicies policies;
    private final GitRepositories repositories;
    private final Containers containers;
    private final Scans scans;
    private final Clock clock;

    public GateService(
            Issues issues,
            GatePolicies policies,
            GitRepositories repositories,
            Containers containers,
            Scans scans,
            Clock clock) {
        this.issues = issues;
        this.policies = policies;
        this.repositories = repositories;
        this.containers = containers;
        this.scans = scans;
        this.clock = clock;
    }

    /**
     * Which policy a write is about: the global one, or one target's override.
     *
     * <p>A record rather than {@code ScanTarget} because the global scope is not a target, and
     * modelling it as one — a repository with no id — is how {@code target_id = 0} ends up
     * meaning two different things in two places.
     */
    public record PolicyScope(String kind, long id) {

        public static PolicyScope global() {
            return new PolicyScope(SCOPE_GLOBAL, NO_TARGET);
        }

        public static PolicyScope of(ScanTarget target) {
            return switch (target) {
                case ScanTarget.Repository repository -> new PolicyScope("repository", repository.id());
                case ScanTarget.Container container -> new PolicyScope("container", container.id());
            };
        }

        public boolean isGlobal() {
            return SCOPE_GLOBAL.equals(kind);
        }
    }

    public record Decision(GateVerdict verdict, ResolvedPolicy policy) {}

    /**
     * Evaluates one target.
     *
     * <p>{@code requested} can only <b>tighten</b> what is stored; refused relaxations come back
     * inside {@link ResolvedPolicy} rather than being dropped, because a pipeline that believes
     * it has switched a rule off needs to find out that it has not.
     */
    @Transactional(readOnly = true)
    public Decision evaluate(ScanTarget target, RequestedPolicy requested) {
        Map<String, StoredPolicy> byScope = activePolicies();
        ResolvedPolicy resolved = PolicyResolution.resolve(
                new PolicyLookup(
                        Optional.ofNullable(byScope.get(scopeKey(target))),
                        Optional.ofNullable(byScope.get(SCOPE_GLOBAL + ":0"))),
                requested,
                Scope.TARGET);

        return new Decision(PolicyGate.evaluate(openIssuesOf(target), resolved.policy()), resolved);
    }

    /** Every target's posture, for the security screen — narrowed to what the caller may see. */
    @Transactional(readOnly = true)
    public SecurityOverview.Overview overview(Visibility visibility) {
        Map<String, StoredPolicy> byScope = activePolicies();

        List<SecurityOverview.NamedTarget> targets = new ArrayList<>();
        Map<ScanTarget, StoredPolicy> policiesByTarget = new HashMap<>();
        repositories.findAll().forEach(repository -> {
            ScanTarget target = new ScanTarget.Repository(repository.getId());
            if (!visibility.permits(target)) {
                return;
            }
            targets.add(new SecurityOverview.NamedTarget(target, TargetNaming.of(repository)));
            Optional.ofNullable(byScope.get(scopeKey(target))).ifPresent(policy -> policiesByTarget.put(target, policy));
        });
        containers.findAll().forEach(container -> {
            ScanTarget target = new ScanTarget.Container(container.getId());
            if (!visibility.permits(target)) {
                return;
            }
            targets.add(new SecurityOverview.NamedTarget(target, TargetNaming.of(container)));
            Optional.ofNullable(byScope.get(scopeKey(target))).ifPresent(policy -> policiesByTarget.put(target, policy));
        });

        return SecurityOverview.build(new SecurityOverview.Input(
                targets,
                policiesByTarget,
                Optional.ofNullable(byScope.get(SCOPE_GLOBAL + ":0")),
                openIssuesByTarget(),
                latestScans()));
    }

    /** Every policy somebody has stored, newest version of each scope, for the screen. */
    @Transactional(readOnly = true)
    public List<GatePolicyEntity> storedPolicies() {
        return policies.findByIsActiveTrue();
    }

    /**
     * Stores a policy for one scope, as a <b>new version</b>.
     *
     * <p>The previous one is superseded rather than updated, because a build that failed in
     * March failed under rules somebody must still be able to read — the verdict returned to
     * the pipeline carries the version number, and a row edited in place would make that
     * number a lie.
     *
     * <p><b>The unique index is the authority on races</b>, not this method. Two administrators
     * saving at the same moment both supersede and both insert; one of the two inserts collides
     * with "at most one active per scope" and comes back as an error the screen shows. Reading
     * the highest version and trusting it would silently keep the loser's policy instead.
     */
    @Transactional
    public GatePolicyEntity store(PolicyScope scope, GatePolicy policy, String note, String author) {
        requireScopeExists(scope);

        policies.supersede(scope.kind(), scope.id());

        GatePolicyEntity stored = new GatePolicyEntity();
        stored.setTargetKind(scope.kind());
        stored.setTargetId(scope.id());
        stored.setVersion(policies.highestVersion(scope.kind(), scope.id()) + 1);
        stored.setIsActive(true);
        // Null, not "unknown": an absent threshold is the severity rule switched off, and
        // `IssueViews.storedPolicy` reads it back that way.
        stored.setFailOnSeverity(policy.failOnSeverity() == null ? null : policy.failOnSeverity().wireName());
        stored.setFailOnKev(policy.failOnKev());
        stored.setFixableOnly(policy.fixableOnly());
        stored.setIncludeTriaged(policy.includeTriaged());
        stored.setIncludeAiReview(policy.includeAiReview());
        stored.setNote(note == null || note.isBlank() ? null : note.trim());
        stored.setCreatedBy(author);
        stored.setCreatedAt(clock.instant());
        return policies.save(stored);
    }

    /**
     * Removes one scope's policy, so it inherits again.
     *
     * <p>Superseded, never deleted, for the same reason a change is: the row says what a build
     * was judged against, and removing an override is itself a decision worth being able to
     * read afterwards.
     *
     * @return whether there was one to remove — the caller answers 404 rather than claiming a
     *     change it did not make
     */
    @Transactional
    public boolean clear(PolicyScope scope) {
        return policies.supersede(scope.kind(), scope.id()) > 0;
    }

    /**
     * A policy for a target that does not exist is a policy nothing will ever read.
     *
     * <p>Refused at the door rather than stored: the scope key is built from an id, so a typo
     * writes a row that resolves for nobody, and the screen would show a rule an operator
     * believes is protecting a repository.
     */
    private void requireScopeExists(PolicyScope scope) {
        boolean exists = switch (scope.kind()) {
            case SCOPE_GLOBAL -> true;
            case "repository" -> repositories.existsById(scope.id());
            case "container" -> containers.existsById(scope.id());
            default -> throw new IllegalArgumentException(
                    "Unknown policy scope: \"" + scope.kind() + "\". Use global, repository or container.");
        };
        if (!exists) {
            throw new java.util.NoSuchElementException(
                    "No " + scope.kind() + " with id " + scope.id() + ".");
        }
    }

    /**
     * One target's open issues.
     *
     * <p><b>This used to build the whole estate's map and keep one entry.</b> Every open issue in
     * the deployment was loaded as a managed entity, grouped by target, and all but one group
     * thrown away — on the endpoint a pipeline calls on every build, against a {@code state}
     * column that carried no index until the migration added beside this change.
     *
     * <p>The verdict is unchanged, and {@code GateDatabaseTest} is what says so: it pinned the
     * numbers before the query moved.
     */
    private List<GateIssue> openIssuesOf(ScanTarget target) {
        String open = IssueState.OPEN.wireName();
        List<IssueEntity> rows = switch (target) {
            case ScanTarget.Repository repository -> issues.findByStateAndRepoId(open, repository.id());
            case ScanTarget.Container container ->
                    issues.findByStateAndRepoIdIsNullAndContainerId(open, container.id());
        };
        return rows.stream().map(IssueViews::forGate).toList();
    }

    /** Every target's open issues, for the overview — which is the one caller that needs them all. */
    private Map<ScanTarget, List<GateIssue>> openIssuesByTarget() {
        Map<ScanTarget, List<GateIssue>> byTarget = new HashMap<>();
        // **Projected, because this one is estate-wide.** Its per-target sibling above reads one
        // target's issues and can afford entities; this reads every open issue in the deployment,
        // and the dashboard opens on every sign-in. Ten columns instead of the row, measured by
        // `ReadCostSweepTest`.
        for (IssueRows.GateRow row : issues.findByState(IssueState.OPEN.wireName(), IssueRows.GateRow.class)) {
            targetOf(row).ifPresent(target ->
                    byTarget.computeIfAbsent(target, key -> new ArrayList<>()).add(IssueViews.forGate(row)));
        }
        return byTarget;
    }

    private Map<ScanTarget, SecurityOverview.LatestScan> latestScans() {
        Map<ScanTarget, SecurityOverview.LatestScan> latest = new HashMap<>();
        scans.findLatestPerRepository()
                .forEach(row -> latestScan(row).ifPresent(scan ->
                        latest.put(new ScanTarget.Repository(((Number) row[0]).longValue()), scan)));
        scans.findLatestPerContainer()
                .forEach(row -> latestScan(row).ifPresent(scan ->
                        latest.put(new ScanTarget.Container(((Number) row[0]).longValue()), scan)));
        return latest;
    }

    /**
     * Empty when the stored status is not one this version knows.
     *
     * <p>Dropping the scan rather than guessing: the overview reads the status to say "never
     * scanned", "last scan failed" or "green", and an unreadable value mapped to any of the
     * three would be a confident wrong answer on a security screen.
     */
    private static Optional<SecurityOverview.LatestScan> latestScan(Object[] row) {
        return ScanStatus.fromWireName((String) row[2])
                .map(status -> new SecurityOverview.LatestScan(
                        ((Number) row[1]).longValue(), status, (Instant) row[3]));
    }

    private Map<String, StoredPolicy> activePolicies() {
        Map<String, StoredPolicy> byScope = new HashMap<>();
        for (GatePolicyEntity policy : policies.findByIsActiveTrue()) {
            byScope.put(
                    policy.getTargetKind() + ":" + (policy.getTargetId() == null ? 0 : policy.getTargetId()),
                    IssueViews.storedPolicy(policy));
        }
        return byScope;
    }

    private static Optional<ScanTarget> targetOf(IssueEntity issue) {
        if (issue.getRepoId() != null) {
            return Optional.of(new ScanTarget.Repository(issue.getRepoId()));
        }
        if (issue.getContainerId() != null) {
            return Optional.of(new ScanTarget.Container(issue.getContainerId()));
        }
        return Optional.empty();
    }

    /** The same attribution, from a projected row. */
    private static Optional<ScanTarget> targetOf(IssueRows.GateRow row) {
        if (row.repoId() != null) {
            return Optional.of(new ScanTarget.Repository(row.repoId()));
        }
        if (row.containerId() != null) {
            return Optional.of(new ScanTarget.Container(row.containerId()));
        }
        return Optional.empty();
    }

    private static String scopeKey(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> "repository:" + repository.id();
            case ScanTarget.Container container -> "container:" + container.id();
        };
    }
}

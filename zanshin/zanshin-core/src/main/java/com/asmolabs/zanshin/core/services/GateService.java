package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.gate.GateIssue;
import com.asmolabs.zanshin.common.domain.gate.GateVerdict;
import com.asmolabs.zanshin.common.domain.gate.PolicyGate;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution.PolicyLookup;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution.ResolvedPolicy;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution.Scope;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution.StoredPolicy;
import com.asmolabs.zanshin.common.domain.gate.RequestedPolicy;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.persistence.GatePolicyEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GatePolicies;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
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

    private final Issues issues;
    private final GatePolicies policies;
    private final GitRepositories repositories;
    private final Containers containers;
    private final Scans scans;

    public GateService(
            Issues issues,
            GatePolicies policies,
            GitRepositories repositories,
            Containers containers,
            Scans scans) {
        this.issues = issues;
        this.policies = policies;
        this.repositories = repositories;
        this.containers = containers;
        this.scans = scans;
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

        List<GateIssue> scoped = openIssuesByTarget().getOrDefault(target, List.of());
        return new Decision(PolicyGate.evaluate(scoped, resolved.policy()), resolved);
    }

    /** Every target's posture, for the security screen. */
    @Transactional(readOnly = true)
    public SecurityOverview.Overview overview() {
        Map<String, StoredPolicy> byScope = activePolicies();

        List<SecurityOverview.NamedTarget> targets = new ArrayList<>();
        Map<ScanTarget, StoredPolicy> policiesByTarget = new HashMap<>();
        repositories.findAll().forEach(repository -> {
            ScanTarget target = new ScanTarget.Repository(repository.getId());
            targets.add(new SecurityOverview.NamedTarget(target, TargetNaming.of(repository)));
            Optional.ofNullable(byScope.get(scopeKey(target))).ifPresent(policy -> policiesByTarget.put(target, policy));
        });
        containers.findAll().forEach(container -> {
            ScanTarget target = new ScanTarget.Container(container.getId());
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

    private Map<ScanTarget, List<GateIssue>> openIssuesByTarget() {
        Map<ScanTarget, List<GateIssue>> byTarget = new HashMap<>();
        for (IssueEntity issue : issues.findByState(IssueState.OPEN.wireName())) {
            targetOf(issue).ifPresent(target ->
                    byTarget.computeIfAbsent(target, key -> new ArrayList<>()).add(IssueViews.forGate(issue)));
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

    private static String scopeKey(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> "repository:" + repository.id();
            case ScanTarget.Container container -> "container:" + container.id();
        };
    }
}

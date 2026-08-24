package com.asmolabs.vectispire.common.domain.gate;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Pass/fail verdict of a target's backlog against a policy.
 *
 * <p>This is what makes Vectispire usable from a pipeline rather than only from a browser: a CI
 * job asks "given what you know about this target, should this build fail?" and gets back a
 * reasoned verdict.
 *
 * <p>Pure functions over a list of issues — no HTTP, no session — so the semantics can be
 * tested exhaustively, and so the same evaluation serves the gate endpoint, the Security
 * screen's badge and the notification threshold. Reimplementing the rule in SQL for one of the
 * three would make it diverge the first time a flag was added.
 *
 * <p><b>Quality findings never fail a build, and there is no flag to change that.</b> A quality
 * backlog is voluminous by nature, and a gate that turns red the day somebody switches on a
 * linter is a gate that gets switched off. The absence of an option is the decision: an option
 * would make "quality never blocks" a sentence with an asterisk.
 */
public final class PolicyGate {

    private PolicyGate() {}

    /** Applies {@code policy} to a target's issues and explains the result. */
    public static GateVerdict evaluate(Collection<GateIssue> issues, GatePolicy policy) {
        List<GateIssue> considered = issues.stream().filter(issue -> isConsidered(issue, policy)).toList();

        Map<Severity, Long> countsBySeverity = new EnumMap<>(Severity.class);
        for (GateIssue issue : considered) {
            countsBySeverity.merge(issue.severity(), 1L, Long::sum);
        }

        List<GateVerdict.Violation> violations = new ArrayList<>();
        for (GateIssue issue : considered) {
            if (policy.failOnKev() && issue.kev()) {
                violations.add(violation(issue, GateVerdict.Rule.KEV,
                        "actively exploited vulnerability (CISA KEV catalog)"));
                // One violation per issue is enough to fail the build. Reporting the KEV rule
                // and not the severity one as well keeps the output actionable rather than
                // duplicated.
                continue;
            }
            if (policy.failOnSeverity() != null && issue.severity().isAtLeast(policy.failOnSeverity())) {
                violations.add(violation(issue, GateVerdict.Rule.SEVERITY,
                        "severity " + issue.severity().wireName()
                                + " >= threshold " + policy.failOnSeverity().wireName()));
            }
        }

        return new GateVerdict(violations.isEmpty(), violations, considered.size(), countsBySeverity);
    }

    private static boolean isConsidered(GateIssue issue, GatePolicy policy) {
        if (!issue.open()) {
            return false;
        }
        if (issue.type() != null) {
            boolean counts = switch (issue.type().gateParticipation()) {
                // Quality: unconditional, and the only rule here with no escape hatch.
                case NEVER -> false;
                // AI review: a local model given the repository's own source can be steered by
                // it, so an operator has to opt in before it can fail their build.
                case ON_REQUEST -> policy.includeAiReview();
                case ALWAYS -> true;
            };
            if (!counts) {
                return false;
            }
        }
        if (!policy.includeTriaged() && issue.triage() != null && issue.triage().isSettled()) {
            return false;
        }
        return !policy.fixableOnly() || issue.hasPublishedFix();
    }

    private static GateVerdict.Violation violation(GateIssue issue, GateVerdict.Rule rule, String reason) {
        return new GateVerdict.Violation(
                rule, issue.id(), issue.identifier(), issue.severity(), issue.packageName(), issue.fixVersions(), reason);
    }

    /**
     * A policy requested by a caller can only <b>tighten</b> the stored one.
     *
     * <p>This is a security control, not a convenience: without it any pipeline could send
     * {@code fail_on_severity: null} in its request body and turn anything it likes green.
     *
     * <p>Attempted relaxations are reported back rather than dropped silently — a pipeline that
     * believes it has switched a rule off needs to find out that it has not.
     *
     * @return the policy to apply, and the API names of the relaxations that were refused
     */
    public static Hardened harden(GatePolicy base, RequestedPolicy requested) {
        GatePolicy policy = base;
        List<String> ignoredRelaxations = new ArrayList<>();

        switch (requested.failOnSeverity()) {
            case SeverityRequest.Unset ignored -> {
                // Nothing said, nothing to weigh.
            }
            case SeverityRequest.Disabled ignored -> {
                // Removing the rule is a relaxation — unless there was no rule to remove.
                if (base.failOnSeverity() != null) {
                    ignoredRelaxations.add("fail_on_severity");
                }
            }
            case SeverityRequest.Threshold(Severity wanted) -> {
                if (base.failOnSeverity() == null) {
                    // Adding a rule where there was none is a tightening.
                    policy = policy.withFailOnSeverity(wanted);
                } else if (wanted.isStricterThresholdThan(base.failOnSeverity())) {
                    policy = policy.withFailOnSeverity(wanted);
                } else if (wanted != base.failOnSeverity()) {
                    ignoredRelaxations.add("fail_on_severity");
                }
                // Equal thresholds: neither tightening nor relaxation, nothing to report.
            }
        }

        for (PolicyFlag flag : PolicyFlag.values()) {
            Boolean wanted = requested.flags().get(flag);
            if (wanted == null || wanted == policy.flag(flag)) {
                continue;
            }
            if (wanted == flag.strictValue()) {
                policy = policy.with(flag, wanted);
            } else {
                ignoredRelaxations.add(flag.wireName());
            }
        }

        return new Hardened(policy, List.copyOf(ignoredRelaxations));
    }

    public record Hardened(GatePolicy policy, List<String> ignoredRelaxations) {}
}

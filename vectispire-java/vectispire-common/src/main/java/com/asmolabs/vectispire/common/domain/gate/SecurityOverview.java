package com.asmolabs.zanshin.common.domain.gate;

import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Where each target stands, in one picture.
 *
 * <p><b>The gate verdict was always computed and never shown.</b> It served the gate endpoint,
 * and a team could only learn whether its repository passed by running a build against it —
 * the application knew the answer and kept it to itself.
 *
 * <h2>Two rules shape this implementation</h2>
 *
 * <p><b>The verdict here must be the one the API returns.</b> This class computes no pass/fail
 * of its own: it calls {@link PolicyGate#evaluate} with the same resolution the endpoint uses,
 * over the same issues. A SQL aggregate recounting "open issues above the threshold" would
 * agree today and diverge the first time a flag was added to {@link GatePolicy} — and nobody
 * would notice until a pipeline and a screen contradicted each other about one repository.
 *
 * <p><b>A screen listing N targets must not cost N queries.</b> Both traps are real: resolving
 * a policy per target costs one or two queries each, loading a target's issues costs another.
 * Everything is read once and matched up here — hence a pure function over already-loaded
 * data, rather than a service holding a session.
 *
 * <h2>An empty backlog is not a good posture</h2>
 *
 * <p><b>A target never scanned, or whose last scan failed, is not a target that passes.</b> It
 * is a target nobody has looked at — the worst posture there is, and the one no screen named.
 * An empty backlog passes every policy; saying so without the qualifier would be the most
 * misleading thing this screen could do. That is what {@link TargetPosture#observed()} carries,
 * and why it is a separate field from {@code passed}.
 */
public final class SecurityOverview {

    private SecurityOverview() {}

    /** What the last scan says about how much the verdict can be trusted. */
    public enum Observation {
        OK,
        NEVER_SCANNED,
        LAST_SCAN_FAILED,
        IN_PROGRESS
    }

    /** A target as this screen names it. */
    public record NamedTarget(ScanTarget target, String name) {}

    public record LatestScan(long id, ScanStatus status, Instant createdAt) {}

    /**
     * @param observed whether the verdict rests on a real observation — a target nobody has
     *     successfully scanned produces an empty backlog, and an empty backlog passes
     *     everything
     */
    public record TargetPosture(
            ScanTarget target,
            String name,
            GateVerdict verdict,
            PolicyResolution.ResolvedPolicy policy,
            Observation observation,
            Optional<LatestScan> lastScan,
            boolean passed,
            boolean observed) {}

    public record Overview(
            List<TargetPosture> targets,
            int failingCount,
            int totalCount,
            long kevCount,
            long neverScannedCount,
            long lastScanFailedCount) {

        public Overview {
            targets = List.copyOf(targets);
        }
    }

    /**
     * Everything the screen needs, already read.
     *
     * <p>The global policy is a field of its own rather than a row keyed {@code "global:0"} in
     * the same map as the targets. The original used that magic key, which meant a repository
     * whose scope key ever collided with it would silently inherit the wrong rules.
     *
     * @param openIssues every open issue, read in one go, grouped here rather than per target
     */
    public record Input(
            List<NamedTarget> targets,
            Map<ScanTarget, PolicyResolution.StoredPolicy> policiesByTarget,
            Optional<PolicyResolution.StoredPolicy> globalPolicy,
            Map<ScanTarget, List<GateIssue>> openIssues,
            Map<ScanTarget, LatestScan> latestScans) {}

    /** Assembles the view from already-read data. No queries here, by construction. */
    public static Overview build(Input input) {
        List<TargetPosture> postures = new ArrayList<>(input.targets().size());
        for (NamedTarget named : input.targets()) {
            postures.add(posture(named, input));
        }

        return new Overview(
                postures,
                (int) postures.stream().filter(posture -> !posture.passed()).count(),
                postures.size(),
                // Counted over the *evaluated* issues, not the whole backlog: a KEV discarded by
                // a triage decision or by `fixableOnly` does not weigh on the verdict, and
                // showing it in the same banner would present a number corresponding to nothing.
                postures.stream()
                        .flatMap(posture -> posture.verdict().violations().stream())
                        .filter(violation -> violation.rule() == GateVerdict.Rule.KEV)
                        .count(),
                postures.stream().filter(p -> p.observation() == Observation.NEVER_SCANNED).count(),
                postures.stream().filter(p -> p.observation() == Observation.LAST_SCAN_FAILED).count());
    }

    private static TargetPosture posture(NamedTarget named, Input input) {
        // The same precedence as `PolicyResolution.resolve`, over policies read once. Calling
        // the repository per target is exactly what would make this screen cost 2N queries.
        PolicyResolution.PolicyLookup lookup = new PolicyResolution.PolicyLookup(
                Optional.ofNullable(input.policiesByTarget().get(named.target())), input.globalPolicy());
        PolicyResolution.ResolvedPolicy policy =
                PolicyResolution.resolve(lookup, RequestedPolicy.none(), PolicyResolution.Scope.TARGET);

        Optional<LatestScan> latest = Optional.ofNullable(input.latestScans().get(named.target()));
        Observation observation = observationOf(latest);

        GateVerdict verdict = PolicyGate.evaluate(
                input.openIssues().getOrDefault(named.target(), List.of()), policy.policy());

        return new TargetPosture(
                named.target(),
                named.name(),
                verdict,
                policy,
                observation,
                latest,
                verdict.passed(),
                observation == Observation.OK);
    }

    private static Observation observationOf(Optional<LatestScan> latest) {
        if (latest.isEmpty()) {
            return Observation.NEVER_SCANNED;
        }
        ScanStatus status = latest.get().status();
        if (status == null) {
            return Observation.OK;
        }
        if (status.isInFlight()) {
            return Observation.IN_PROGRESS;
        }
        return status == ScanStatus.FAILED ? Observation.LAST_SCAN_FAILED : Observation.OK;
    }
}

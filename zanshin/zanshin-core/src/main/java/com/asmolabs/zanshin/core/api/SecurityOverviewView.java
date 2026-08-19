package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.gate.GateVerdict;
import com.asmolabs.zanshin.common.domain.gate.PolicyResolution;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The security screen's shape, which is not the domain's.
 *
 * <p><b>Written out rather than serializing {@code SecurityOverview.Overview} directly</b>, and
 * the first version did exactly that. What went over the wire was
 * {@code "target": {"id": 1}} — a sealed interface has no discriminator in JSON, so the client
 * could not tell a repository from an image — {@code "observation": "NEVER_SCANNED"} where it
 * reads {@code never_scanned}, and a nested {@code policy.policy} nobody asked for. The screen
 * would have rendered a table of blanks.
 *
 * <p>The lesson is not about these three fields. A domain record is shaped by the decision it
 * carries; a payload is shaped by what a client reads. They agree by accident until an enum is
 * renamed or a type is made sealed, and the first sign is a screen that stops filling in.
 */
record SecurityOverviewView(
        List<TargetView> targets,
        int failingCount,
        int totalCount,
        long kevCount,
        long neverScannedCount,
        long lastScanFailedCount) {

    /**
     * @param kind {@code repository} or {@code container} — flattened out of the sealed target,
     *     because "which kind" is a question the client asks and JSON does not answer on its own
     */
    record TargetView(
            String kind,
            long targetId,
            String name,
            VerdictView verdict,
            PolicyView policy,
            String observation,
            Instant lastScanAt,
            Long lastScanId,
            boolean passed,
            boolean observed) {}

    record VerdictView(
            boolean passed, int evaluated, List<ViolationView> violations, Map<String, Long> countsBySeverity) {}

    record PolicyView(String source, Integer version) {}

    static SecurityOverviewView of(SecurityOverview.Overview overview) {
        return new SecurityOverviewView(
                overview.targets().stream().map(SecurityOverviewView::targetOf).toList(),
                overview.failingCount(),
                overview.totalCount(),
                overview.kevCount(),
                overview.neverScannedCount(),
                overview.lastScanFailedCount());
    }

    private static TargetView targetOf(SecurityOverview.TargetPosture posture) {
        return new TargetView(
                posture.target() instanceof ScanTarget.Repository ? "repository" : "container",
                switch (posture.target()) {
                    case ScanTarget.Repository repository -> repository.id();
                    case ScanTarget.Container container -> container.id();
                },
                posture.name(),
                new VerdictView(
                        posture.verdict().passed(),
                        posture.verdict().evaluated(),
                        ViolationView.of(posture.verdict().violations()),
                        // Keyed by wire name, not by the enum's own. `CRITICAL` and `critical`
                        // are the same severity to a reader and two different keys to a lookup.
                        posture.verdict().countsBySeverity().entrySet().stream()
                                .collect(Collectors.toMap(entry -> entry.getKey().wireName(), Map.Entry::getValue))),
                new PolicyView(source(posture.policy().source()), posture.policy().version().orElse(null)),
                wire(posture.observation().name()),
                posture.lastScan().map(SecurityOverview.LatestScan::createdAt).orElse(null),
                posture.lastScan().map(SecurityOverview.LatestScan::id).orElse(null),
                posture.passed(),
                posture.observed());
    }

    /**
     * The policy's origin, spelled as the client compares it.
     *
     * <p>{@code built-in} with a hyphen, and it is not a detail: the screen renders "défaut"
     * on an exact match and otherwise prints the raw value followed by a version — so
     * {@code built_in} would have shown "built_in vnull" in the policy column of every target
     * that has no policy of its own, which is most of them on a new install.
     */
    private static String source(PolicyResolution.Source source) {
        return switch (source) {
            case BUILT_IN -> "built-in";
            case TARGET -> "target";
            case GLOBAL -> "global";
        };
    }

    /**
     * An enum constant as the API spells it.
     *
     * <p>Lowercase, and that is the whole convention: a client comparing against {@code
     * "never_scanned"} silently matches nothing when it receives {@code "NEVER_SCANNED"}, and a
     * screen that matches nothing renders its fallback rather than an error.
     */
    private static String wire(String constant) {
        return constant.toLowerCase(Locale.ROOT);
    }
}

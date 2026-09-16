package com.asmolabs.vectispire.common.domain.gate;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.List;
import java.util.Map;

/**
 * The answer a pipeline gets: whether to fail, and why.
 *
 * @param evaluated how many issues the policy actually looked at — the number that explains a
 *     surprising pass, and the one an operator asks for first
 */
public record GateVerdict(
        boolean passed, List<Violation> violations, int evaluated, Map<Severity, Long> countsBySeverity) {

    public GateVerdict {
        violations = List.copyOf(violations);
        countsBySeverity = Map.copyOf(countsBySeverity);
    }

    /**
     * Which rule was tripped, and enough context to act on it without a second call.
     *
     * @param issueId the issue behind the violation, <b>or {@code null} when there is none</b>.
     *     {@link Rule#COVERAGE} is about the examination rather than about a finding: there is no
     *     issue to point at, which is the whole reason it fails. Reporting {@code 0} instead would
     *     hand every consumer an id that looks like one and matches nothing.
     */
    public record Violation(
            Rule rule, Long issueId, String identifier, Severity severity, String packageName, String fixVersions, String reason) {}

    public enum Rule {
        KEV,
        SEVERITY,
        /** No rule reached the target's ecosystems, so nothing was examined. */
        COVERAGE
    }

    /**
     * What code analysis could reach on this target, as far as the verdict is concerned.
     *
     * <p>Passed in rather than looked up, so {@link PolicyGate} stays a pure function over its
     * inputs and the same evaluation keeps serving the endpoint, the posture screen and the sweep.
     *
     * @param uncoveredEcosystems the target's package ecosystems that no installed rule covers.
     *     Empty means nothing to report — which is also what a caller passes when the question
     *     does not apply to it.
     */
    public record Coverage(List<String> uncoveredEcosystems) {

        /**
         * For a caller whose verdict is about one issue rather than about a target.
         *
         * <p>A coverage gap is a property of the examination, and answering "this issue is not
         * acceptable because another language has no rules" would be a category error — it would,
         * for instance, keep a ticket open forever over something its fix cannot change.
         */
        public static final Coverage NOT_APPLICABLE = new Coverage(List.of());

        public Coverage {
            uncoveredEcosystems = List.copyOf(uncoveredEcosystems);
        }
    }
}

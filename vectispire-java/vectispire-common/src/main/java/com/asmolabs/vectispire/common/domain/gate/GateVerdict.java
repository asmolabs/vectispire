package com.asmolabs.zanshin.common.domain.gate;

import com.asmolabs.zanshin.common.domain.issues.Severity;
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

    /** Which rule an issue tripped, and enough context to act on it without a second call. */
    public record Violation(
            Rule rule, long issueId, String identifier, Severity severity, String packageName, String fixVersions, String reason) {}

    public enum Rule {
        KEV,
        SEVERITY
    }
}

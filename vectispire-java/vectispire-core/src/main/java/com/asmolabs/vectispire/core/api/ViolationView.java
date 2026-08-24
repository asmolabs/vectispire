package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.gate.GateVerdict;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Locale;

/**
 * A gate violation as the wire spells it.
 *
 * <p>Three fields differ from the domain record, and all three matter to something that reads
 * them without a human in the loop:
 *
 * <ul>
 *   <li>{@code rule} is {@code kev} or {@code severity}. The enum serializes as {@code KEV}, and
 *       both the dashboard and any pipeline that branches on the rule compare lowercase.
 *   <li>{@code severity} is the wire name. {@code HIGH} matches none of the client's colours and
 *       none of a pipeline's thresholds.
 *   <li>{@code package} is what the client calls it. It cannot be a Java field name, so it can
 *       only arrive through an annotation — and silently arrives as {@code packageName} without.
 * </ul>
 *
 * <p>This is the payload a build failure is explained by. Getting it wrong does not break the
 * verdict, it breaks the sentence that tells somebody why their build stopped.
 */
record ViolationView(
        String rule,
        long issueId,
        String identifier,
        String severity,
        @JsonProperty("package") String packageName,
        String fixVersions,
        String reason) {

    static List<ViolationView> of(List<GateVerdict.Violation> violations) {
        return violations.stream().map(ViolationView::of).toList();
    }

    static ViolationView of(GateVerdict.Violation violation) {
        return new ViolationView(
                violation.rule().name().toLowerCase(Locale.ROOT),
                violation.issueId(),
                violation.identifier(),
                violation.severity() == null ? null : violation.severity().wireName(),
                violation.packageName(),
                violation.fixVersions(),
                violation.reason());
    }
}

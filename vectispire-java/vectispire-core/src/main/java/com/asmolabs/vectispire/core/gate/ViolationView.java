package com.asmolabs.vectispire.core.gate;

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
 * <p><b>{@code issueId} is nullable, and that is a fourth difference from the domain record.</b>
 * The coverage rule fails on the absence of an examination rather than on a finding, so there is
 * no issue to point at. It was a primitive here, which the published document read as "always
 * sent" — a promise this API would have broken the first time that rule fired.
 *
 * <p>This is the payload a build failure is explained by. Getting it wrong does not break the
 * verdict, it breaks the sentence that tells somebody why their build stopped.
 *
 * <p><b>Part of the gate module's API, and public for it</b> (decision 0028). It was a
 * package-private record of {@code core.api}, shared by the gate's routes and the dashboard's; the
 * dashboard is {@code posture}'s, which may use {@code gate}, and a record in either module's {@code
 * web} package would be hidden from the other.
 */
public record ViolationView(
        String rule,
        Long issueId,
        String identifier,
        String severity,
        @JsonProperty("package") String packageName,
        String fixVersions,
        String reason) {

    public static List<ViolationView> of(List<GateVerdict.Violation> violations) {
        return violations.stream().map(ViolationView::of).toList();
    }

    public static ViolationView of(GateVerdict.Violation violation) {
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

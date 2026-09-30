package com.asmolabs.vectispire.core.rules.web;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * The 409 of a rule-set change that would resolve open issues, as the OpenAPI document describes it —
 * never built: {@code ApiExceptionHandler} writes the RFC 9457 problem, and the conflict's members join
 * it as extension members. Declared so that {@code affectedIssues} and {@code losingIssues} have a
 * schema a client binds rather than restating by hand.
 */
final class RuleSetRefusals {

    private RuleSetRefusals() {}

    /** {@code urn:vectispire:problem:rule-set-activation-loses-issues}. */
    @Schema(name = "RuleSetLosesIssuesProblem", description = "A rule-set-activation-loses-issues refusal: an RFC "
            + "9457 problem whose affectedIssues member is the number of open issues the change would resolve at "
            + "the next scan, read at the refusal — the value to send back as acceptLosing — and whose "
            + "losingIssues member names the rule identifiers leaving with them.")
    record LosesIssues(String type, String title, int status, String detail, String instance,
            long affectedIssues, List<String> losingIssues) {}
}

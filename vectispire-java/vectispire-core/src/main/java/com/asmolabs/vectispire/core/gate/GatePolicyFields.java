package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.gate.PolicyFlag;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SeverityRequest;
import com.asmolabs.vectispire.common.domain.issues.Severity;

/**
 * What a caller sent about a gate policy, every field boxed — and <b>the one reading of it</b>.
 *
 * <p>Two routes take a policy: the verdict, which asks for one evaluation under a stricter policy
 * than the stored one, and the policy screen, which replaces a stored policy wholesale. Each parsed
 * its body in its own controller, with its own copy of the severity rule, and the copies had already
 * diverged — one trimmed {@code " none "}, the other refused it as an unknown severity. The two
 * readings below differ on purpose, and only where their routes do: what an absent field means.
 *
 * @param failOnSeverity a severity, or {@code "none"} for "the severity rule is off"
 * @param failOnUncoveredLanguages never sent to the verdict route, whose body does not carry it
 */
public record GatePolicyFields(
        String failOnSeverity,
        Boolean failOnKev,
        Boolean fixableOnly,
        Boolean includeTriaged,
        Boolean includeAiReview,
        Boolean failOnUncoveredLanguages,
        Boolean includePlugins) {

    /**
     * Read as one verdict's request: <b>an absent field was not mentioned</b>.
     *
     * <p>{@code null} and a value differ, and that is the whole point: without it, any caller
     * omitting {@code fail_on_severity} would look like it was asking for the schema's default and
     * would be told its request had been refused, on every single call.
     */
    public RequestedPolicy asRequest() {
        RequestedPolicy requested = RequestedPolicy.none();
        if (failOnSeverity != null) {
            requested = requested.with(severity(failOnSeverity));
        }
        requested = withFlag(requested, PolicyFlag.FAIL_ON_KEV, failOnKev);
        requested = withFlag(requested, PolicyFlag.FIXABLE_ONLY, fixableOnly);
        requested = withFlag(requested, PolicyFlag.INCLUDE_TRIAGED, includeTriaged);
        requested = withFlag(requested, PolicyFlag.INCLUDE_AI_REVIEW, includeAiReview);
        requested = withFlag(requested, PolicyFlag.FAIL_ON_UNCOVERED_LANGUAGES, failOnUncoveredLanguages);
        requested = withFlag(requested, PolicyFlag.INCLUDE_PLUGINS, includePlugins);
        return requested;
    }

    /**
     * Read as a stored policy replacing the previous one: <b>every field is read, none is defaulted
     * from what is already stored</b>. A partial update would make "leave this alone" and "set it to
     * false" the same request, and the two differ by a build that fails.
     *
     * <p>The severity is refused when absent rather than defaulted: a field nobody sent would
     * silently reinstate the built-in threshold under a version number that says somebody chose it.
     */
    public GatePolicy asReplacement() {
        if (failOnSeverity == null || failOnSeverity.isBlank()) {
            throw new IllegalArgumentException(
                    "\"fail_on_severity\" is required — a severity, or \"none\" to switch the rule off.");
        }
        return new GatePolicy(
                switch (severity(failOnSeverity)) {
                    case SeverityRequest.Threshold threshold -> threshold.severity();
                    // The difference is not cosmetic: null is the policy that blocks on actively
                    // exploited findings alone.
                    case SeverityRequest.Disabled disabled -> null;
                    case SeverityRequest.Unset unset -> throw new IllegalStateException("A sent severity is never unset.");
                },
                required(failOnKev, "fail_on_kev"),
                required(fixableOnly, "fixable_only"),
                required(includeTriaged, "include_triaged"),
                required(includeAiReview, "include_ai_review"),
                // **The one field that may be absent, and for the opposite reason to the others.**
                // They are refused when missing because a stored value would be silently
                // reinstated under a version number saying somebody chose it. This flag has no
                // prior value to reinstate: it did not exist before, every stored policy has it
                // off, and absent means the behaviour the caller already had. Refusing it would
                // break every pipeline that writes a policy today, over a rule none of them can
                // yet know about.
                failOnUncoveredLanguages != null && failOnUncoveredLanguages,
                // Absent for the same reason, and newer still: every stored policy has it off, and
                // a pipeline that writes a policy today cannot know it exists.
                includePlugins != null && includePlugins);
    }

    /**
     * {@code "none"} switches the severity rule off; anything else is a threshold.
     *
     * <p>An unreadable severity is refused: {@code Severity.of} answers {@code UNKNOWN}, which ranks
     * last and would fail nothing. A pipeline that typed "hgh" must be told, not quietly given a gate
     * that passes everything — and a policy stored from the typo would do the same to every build.
     */
    static SeverityRequest severity(String value) {
        if ("none".equalsIgnoreCase(value.trim())) {
            return new SeverityRequest.Disabled();
        }
        Severity severity = Severity.of(value);
        if (severity == Severity.UNKNOWN) {
            throw new IllegalArgumentException("Unknown severity: \"" + value + "\".");
        }
        return new SeverityRequest.Threshold(severity);
    }

    private static boolean required(Boolean value, String field) {
        if (value == null) {
            throw new IllegalArgumentException("\"" + field + "\" is required.");
        }
        return value;
    }

    private static RequestedPolicy withFlag(RequestedPolicy requested, PolicyFlag flag, Boolean value) {
        return value == null ? requested : requested.with(flag, value);
    }
}

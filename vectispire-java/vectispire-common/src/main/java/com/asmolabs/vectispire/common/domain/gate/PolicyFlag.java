package com.asmolabs.vectispire.common.domain.gate;

/**
 * The boolean knobs of a gate policy, each carrying the value that <em>tightens</em> it.
 *
 * <p><b>"Stricter" does not mean "true".</b> Turning {@link #FIXABLE_ONLY} on shrinks the set
 * of issues evaluated, so {@code false} is the strict end of that one. The NestJS version kept
 * this in a table beside a second table mapping each flag to its API name; two lists over the
 * same set, either of which could gain a member the other did not. Both properties travel with
 * the constant here, so a fifth flag cannot be half-declared.
 */
public enum PolicyFlag {

    /** Fail on any open issue in the CISA KEV catalog, whatever its severity. */
    FAIL_ON_KEV("fail_on_kev", true),

    /** Also count issues a human has already settled. */
    INCLUDE_TRIAGED("include_triaged", true),

    /** Let AI review findings weigh on the verdict. */
    INCLUDE_AI_REVIEW("include_ai_review", true),

    /** Fail only on issues that have a published fix — which evaluates fewer of them. */
    FIXABLE_ONLY("fixable_only", false);

    private final String wireName;
    private final boolean strictValue;

    PolicyFlag(String wireName, boolean strictValue) {
        this.wireName = wireName;
        this.strictValue = strictValue;
    }

    /** The name reported back to callers. The API speaks snake_case and keeps doing so. */
    public String wireName() {
        return wireName;
    }

    /** The value that makes the policy stricter, and is therefore the one a caller may set. */
    public boolean strictValue() {
        return strictValue;
    }
}

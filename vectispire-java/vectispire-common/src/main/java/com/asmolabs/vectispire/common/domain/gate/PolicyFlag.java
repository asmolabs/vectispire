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
    FIXABLE_ONLY("fixable_only", false),

    /**
     * Refuse a verdict whose code analysis reached none of the target's ecosystems.
     *
     * <p><b>Off by default, and that is the decision rather than the setting.</b> A target no rule
     * covers reports no code finding, and an empty result passes every policy — the one green this
     * product exists to distinguish from a clean one. Turning this on makes "not looked at" block
     * instead of inform.
     *
     * <p>It ships off because switching it on for everyone would fail every existing build at the
     * first deployment, over a condition nobody had been told about. The banner came first, on the
     * screens where the absence reads as good news; this is the second half, and it is opt-in.
     */
    FAIL_ON_UNCOVERED_LANGUAGES("fail_on_uncovered_languages", true);

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

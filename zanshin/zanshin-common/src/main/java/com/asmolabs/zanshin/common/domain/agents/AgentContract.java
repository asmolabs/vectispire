package com.asmolabs.zanshin.common.domain.agents;

/**
 * The version of the contract between Zanshin and its agents.
 *
 * <p><b>An agent on an older version must be able to refuse cleanly.</b> Without this number
 * an agent speaking the old protocol receives a task it misreads and returns a plausible but
 * wrong result — a scan declaring a repository clean because it did not understand what it was
 * asked to look for.
 *
 * <p>The number changes <b>only</b> when the old behaviour becomes incorrect. Adding an
 * optional field is not a break: an agent that ignores it does exactly what it did before.
 */
public final class AgentContract {

    private AgentContract() {}

    public static final String VERSION = "1";

    /**
     * Is this contract compatible with ours?
     *
     * <p>Strict equality, deliberately. A looser comparison — "same major" — looks welcoming
     * and moves the question elsewhere: it would then be necessary to decide, for every field
     * added, whether an agent that ignores it is still correct. The refusal is loud, the fix is
     * a deployment, and the operator knows what to do.
     */
    public static boolean isCompatible(String announced) {
        return announced != null && VERSION.equals(announced.trim());
    }
}

/**
 * The version of the contract between Zanshin and its agents.
 *
 * **An agent on an older version must be able to refuse cleanly.** Without this number, an
 * agent speaking the old protocol would receive a task it misreads and return a plausible
 * but wrong result — a scan declaring a repository clean because it did not understand what
 * it was asked to look for.
 *
 * The number changes **only** when the old behaviour becomes incorrect: adding an optional
 * field is not a break, since an agent that ignores it does exactly what it did before.
 */
export const CONTRACT_VERSION = '1';

/**
 * Is this contract compatible with ours?
 *
 * Strict equality, deliberately. A looser comparison — "same major" — looks welcoming and
 * moves the question elsewhere: it would then be necessary to decide, for every field
 * added, whether an agent that ignores it is still correct. The refusal is loud, the fix is
 * a deployment, and the operator knows what to do.
 */
export function isCompatibleContract(announced: string): boolean {
    return announced.trim() === CONTRACT_VERSION;
}

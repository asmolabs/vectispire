package com.asmolabs.vectispire.core.audit;

/**
 * A verification found the audit trail tampered with: the chain breaks, or the mirror holds entries
 * the table lost.
 *
 * <p><b>Owned by {@code audit}, heard by {@code siem}.</b> The verification used to call the SIEM
 * directly, while the SIEM listens to the audit log it verifies — a cycle between the foundation and
 * a domain above it (decision 0026). Published as an application event, the dependency points one
 * way: the SIEM knows this record, the audit log knows nobody.
 *
 * <p><b>Published synchronously, outside any transaction</b> — see {@code
 * AuditLogQueryService#verify} for why the listener is a plain {@code @EventListener} and not an
 * after-commit one.
 *
 * @param brokenAt the entry where the chain stops verifying, or {@code null} when the chain holds and
 *     only the mirror disagrees
 * @param missingFromTable entries the mirror holds and the table does not
 */
public record AuditChainBroken(String brokenAt, int missingFromTable) {

    /** Worded for a SOC analyst reading one line, who has neither the screen nor the table. */
    public String describe() {
        return brokenAt != null
                ? "The audit chain breaks at entry " + brokenAt
                : missingFromTable + " entr" + (missingFromTable == 1 ? "y" : "ies")
                        + " held by the mirror are missing from the table";
    }
}

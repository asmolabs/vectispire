package com.asmolabs.vectispire.core.reportplugins;

import java.time.Instant;

/**
 * A manifest's withdrawal, as every document it produced carries it (decision 0035 §4, lot R7): when, by whom,
 * and why — the governor's justification, as written.
 *
 * @param withdrawnBy the platform governor who withdrew it, by user name — as the registry and the run's {@code
 *     requestedBy} name people
 */
public record ReportWithdrawal(Instant withdrawnAt, String withdrawnBy, String withdrawalJustification) {}

package com.asmolabs.vectispire.common.domain.targets;

/**
 * The issues and scans whose target no longer exists, and what hangs off them.
 *
 * <p>Left by deletions from before the foreign keys were enforced — MySQL before V19, SQLite before
 * the pragma — or by a repair run at the prompt. Swept at startup and by the maintenance tick,
 * through the same listeners and in the same order as a {@link TargetDeleted}, so the two purges
 * cannot come to disagree about what a target's rows are. Grants and gate policies are not part of
 * it: they have no parent to be orphaned from, and never were swept.
 */
public record OrphanedTargetRows() implements TargetPurge {}

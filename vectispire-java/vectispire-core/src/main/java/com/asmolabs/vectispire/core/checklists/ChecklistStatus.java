package com.asmolabs.vectispire.core.checklists;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Where a revision of a project's checklist stands (decision 0032 §5).
 *
 * <pre>
 *             submit                 sign off
 *   draft ────────────► submitted ────────────► signed_off
 *     ▲                     │                       │
 *     └──── return ─────────┘                       │ reopen
 *     ▲  (with a reason)                            ▼
 *     └────────────────────────────── new revision, draft
 * </pre>
 *
 * <p>{@link #SUPERSEDED} is an open revision set aside by the next one — a move to another version.
 * A signed-off revision is never superseded: what was signed stays signed.
 */
public enum ChecklistStatus {
    DRAFT,
    SUBMITTED,
    SIGNED_OFF,
    SUPERSEDED;

    /** The statuses that hold the project's one open slot. */
    static final List<String> OPEN = List.of(DRAFT.wireName(), SUBMITTED.wireName());

    /** The value stored in {@code t_checklist.status} and sent on the wire. */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    boolean isOpen() {
        return this == DRAFT || this == SUBMITTED;
    }

    /** A stored value this version does not know is a defect of the row: only this enum writes one. */
    static ChecklistStatus ofStored(String stored) {
        return Arrays.stream(values())
                .filter(status -> status.wireName().equals(stored))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("A checklist has an unknown status: " + stored));
    }
}

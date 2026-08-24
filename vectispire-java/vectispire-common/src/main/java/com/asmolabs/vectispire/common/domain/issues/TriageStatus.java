package com.asmolabs.vectispire.common.domain.issues;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Where an issue stands with the humans.
 *
 * <p>{@link #isSettled()} is the property the gate actually consults. The NestJS version
 * asked it as "is the status neither {@code under_review} nor {@code affected}" — a double
 * negative over a list of exceptions, which is the kind of condition that acquires a wrong
 * third term the day a fifth status is added. Here a new constant has to declare whether it
 * settles anything, and the gate does not change.
 */
public enum TriageStatus {

    /** Somebody is looking at it. It still counts against a gate. */
    UNDER_REVIEW(false),

    /** Judged to apply. It counts, which is the point of saying so. */
    AFFECTED(false),

    /** Exemption or dismissal requested, awaiting approval by a Security Champion or CISO. Still counts against a gate. */
    PENDING_APPROVAL(false),

    /** Argued not to apply. Settled: it stops failing builds. */
    NOT_AFFECTED(true),

    /** Resolved. Settled. */
    FIXED(true);

    private final boolean settled;

    TriageStatus(boolean settled) {
        this.settled = settled;
    }

    /**
     * Whether a human decision has taken this issue out of the way.
     *
     * <p><b>A settled issue does not fail a build by default.</b> An argued {@code
     * NOT_AFFECTED} judgement is the whole point of triage; a gate that ignored it would send
     * teams back to switching the gate off, which is strictly worse than a gate that trusts
     * them.
     */
    public boolean isSettled() {
        return settled;
    }

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * The statuses that leave an issue in the way, by wire name.
     *
     * <p>Derived from {@link #isSettled()} rather than listed: a second list could disagree with
     * the flag, and the disagreement would decide whether a dismissed issue counts as late.
     */
    public static List<String> unsettledWireNames() {
        return Arrays.stream(values()).filter(status -> !status.isSettled()).map(TriageStatus::wireName).toList();
    }

    public static Optional<TriageStatus> fromWireName(String value) {
        return value == null
                ? Optional.empty()
                : Arrays.stream(values())
                        .filter(status -> status.wireName().equals(value.trim().toLowerCase(Locale.ROOT)))
                        .findFirst();
    }
}

package com.asmolabs.vectispire.core.forges.internal;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/** A change-review reading's state, {@code t_forge_review_reading.state}. */
public enum ReviewState {
    /** Claimed, never read: the rule has nothing to read yet. */
    PENDING,
    /** The forge answered; the evidence says what. */
    READ,
    /** The forge would not answer about the project; the reason says why. */
    UNREADABLE,
    /** No connection imported or discovered the repository. */
    UNLINKED;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** A stored state read back; one this version does not know is none of these, and read as never read. */
    public static Optional<ReviewState> ofStored(String value) {
        return Arrays.stream(values()).filter(state -> state.wireName().equals(value)).findFirst();
    }
}

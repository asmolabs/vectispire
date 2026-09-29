package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Who wrote a checklist answer: a person, or Vectispire from a measurement (decision 0032, amendment
 * "the scans answer the lines they measure").
 *
 * <p><b>A kind, never a name.</b> The author's name is free text — an account may be called
 * "Vectispire" — so telling an automatic answer from a person's by comparing names would let anybody so
 * named pass for the product, or have their own answers replaced by it as if they were its. Every
 * reader decides by this kind: the scans replace only {@link #SYSTEM}'s answers, four-eyes counts only
 * {@link #PERSON}'s authors, and a document marks each automatic answer.
 */
public enum AnswerAuthor {

    /** An account, named by its username and identified by its id. */
    PERSON,

    /** Vectispire itself: no account, no role, and an answer resting on the measurement that produced it. */
    SYSTEM;

    /**
     * The name a system answer is written under, for a reader who shows names — never how one is
     * recognised, which is {@link #SYSTEM}.
     */
    public static final String SYSTEM_NAME = "Vectispire";

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** A stored kind; empty for one this version does not know. */
    public static Optional<AnswerAuthor> ofStored(String stored) {
        return Arrays.stream(values()).filter(kind -> kind.wireName().equals(stored)).findFirst();
    }

    /**
     * Whether a stored kind is the system's. A kind this version does not know is not: read as a
     * person's, its answer is never replaced by the scans — the safe way to err.
     */
    public static boolean isSystem(String stored) {
        return ofStored(stored).orElse(PERSON) == SYSTEM;
    }
}

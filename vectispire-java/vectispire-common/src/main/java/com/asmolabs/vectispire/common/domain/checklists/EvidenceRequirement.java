package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * What proof a line asks for before its checklist can be submitted, and for how long a proof holds.
 *
 * <p>Part of the item's content digest: a line that starts asking for a file asks for something
 * else, and an answer carried onto it must be confirmed (decision 0032 §4).
 */
public record EvidenceRequirement(Kind kind, Optional<Integer> validityMonths) {

    /** Ten years: a proof said to hold longer is one nobody means to renew. */
    public static final int MAX_VALIDITY_MONTHS = 120;

    public static final EvidenceRequirement NONE = new EvidenceRequirement(Kind.NONE, Optional.empty());

    public enum Kind {
        NONE,
        LINK_OR_FILE,
        FILE;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public EvidenceRequirement {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(validityMonths, "validityMonths");
        if (kind == Kind.NONE && validityMonths.isPresent()) {
            throw new InvalidInputException("A validity applies to a proof, and this line asks for none.");
        }
        validityMonths.filter(months -> months < 1 || months > MAX_VALIDITY_MONTHS).ifPresent(months -> {
            throw new InvalidInputException("A proof's validity is between 1 and " + MAX_VALIDITY_MONTHS
                    + " months; " + months + " is not.");
        });
    }

    /** The form the content digest reads: the kind, and the validity when there is one. */
    String canonical() {
        return kind.wireName() + validityMonths.map(months -> "/" + months).orElse("");
    }
}

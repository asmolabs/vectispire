package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * What a person answers on a checklist line, whatever words the template uses for it.
 *
 * <p>A closed set rather than the template's own words: a rule reconciling an answer with a
 * measurement (decision 0032 §6), a submission counting the negative lines, a document rendered in
 * another template's language — each needs to know what an answer <em>means</em>, and "Non",
 * "Nee" and "Not yet" only mean something through the version's {@link AnswerWords}.
 */
public enum ChecklistAnswer {
    YES,
    NO,
    /** Offered only by a version whose importer mapped a word to it (decision 0032, question 1). */
    NOT_APPLICABLE;

    /**
     * A negative answer without its reason is the line the reader of the document needs most, and
     * "not applicable" without a justification is an exclusion nobody argued — the one the
     * statement of applicability already refuses ({@code EXCLUDED_WITHOUT_JUSTIFICATION}).
     */
    public boolean requiresComment() {
        return this != YES;
    }

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** The answer as the API names it, or a refusal listing the three. */
    public static ChecklistAnswer parse(String value) {
        String normalized = value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(answer -> answer.wireName().equals(normalized))
                .findFirst()
                .orElseThrow(() -> new InvalidInputException("An answer is one of "
                        + Arrays.stream(values()).map(ChecklistAnswer::wireName).collect(Collectors.joining(", "))
                        + (normalized.isEmpty() ? "" : "; \"" + BoundedText.clip(value.strip(), 40) + "\" is not one of them")
                        + "."));
    }
}

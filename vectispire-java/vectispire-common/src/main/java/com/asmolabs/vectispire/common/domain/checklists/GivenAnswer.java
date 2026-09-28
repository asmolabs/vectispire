package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.Objects;
import java.util.Optional;

/**
 * An answer to one line as a person gives it: the value and its comment, checked against what the
 * version offers before anything is written.
 *
 * <p>The author and the instant are not here: they are the principal and the clock of the write,
 * never values a caller hands in (decision 0032 §5).
 */
public record GivenAnswer(ChecklistAnswer value, Optional<String> comment) {

    /** Bounded before the write (decision 0032 §2); longer is a document, attached as evidence. */
    public static final int MAX_COMMENT = 4_000;

    public GivenAnswer {
        Objects.requireNonNull(value, "value");
        comment = Objects.requireNonNull(comment, "comment")
                .map(text -> BoundedText.optional(text, MAX_COMMENT, "The comment"));
        if (value.requiresComment() && comment.isEmpty()) {
            throw new InvalidInputException(value == ChecklistAnswer.NO
                    ? "A \"no\" needs a comment saying why: it is the line the reader of the checklist needs most."
                    : "\"Not applicable\" needs a comment saying why the line does not apply.");
        }
    }

    /**
     * The answer, refused when the version does not offer it.
     *
     * @throws InvalidInputException not applicable on a version that does not offer it, a negative
     *     answer without its comment, a comment past {@value #MAX_COMMENT} characters
     */
    public static GivenAnswer of(ChecklistAnswer value, String comment, AnswerWords offered) {
        if (value == ChecklistAnswer.NOT_APPLICABLE && !offered.offersNotApplicable()) {
            throw new InvalidInputException("This version of the template does not offer \"not applicable\".");
        }
        return new GivenAnswer(value, Optional.ofNullable(comment));
    }
}

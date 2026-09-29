package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * The template's own words for each answer, mapped by the person importing it.
 *
 * <p><b>Mapped by a person, never recognised.</b> The reader proposes the values of the answer
 * column's validation list and stops there: deciding that "Oui" is yes would be one organisation's
 * vocabulary built into the product, and the next template, in another language, would be read
 * wrong without a word of warning. The renderer writes these words back into the answer cells, so
 * they are kept exactly as mapped — trimmed, never re-cased.
 *
 * <p><b>"Not applicable" is offered only when a word is mapped to it</b> (decision 0032, question
 * 1). The template's value list may have no such word; the importer then supplies one, which the
 * renderer writes without touching the list — so the word need not be one of the list's values.
 */
public record AnswerWords(String yes, String no, Optional<String> notApplicable) {

    public static final int MAX_WORD = 255;

    public AnswerWords {
        yes = BoundedText.required(yes, MAX_WORD, "The word for yes");
        no = BoundedText.required(no, MAX_WORD, "The word for no");
        notApplicable = Objects.requireNonNull(notApplicable)
                .map(word -> BoundedText.required(word, MAX_WORD, "The word for not applicable"));
        if (same(yes, no)) {
            throw new InvalidInputException("Yes and no are mapped to the same word, \"" + yes + "\": an answer "
                    + "written in the workbook could not be read back.");
        }
        String yesWord = yes;
        String noWord = no;
        notApplicable.filter(word -> same(word, yesWord) || same(word, noWord)).ifPresent(word -> {
            throw new InvalidInputException("Not applicable is mapped to \"" + word + "\", a word already mapped to "
                    + "yes or no.");
        });
    }

    public static AnswerWords of(String yes, String no) {
        return new AnswerWords(yes, no, Optional.empty());
    }

    public boolean offersNotApplicable() {
        return notApplicable.isPresent();
    }

    /**
     * The word the renderer writes for an answer.
     *
     * @throws InvalidInputException "not applicable" on a version that does not offer it
     */
    public String word(ChecklistAnswer answer) {
        return switch (answer) {
            case YES -> yes;
            case NO -> no;
            case NOT_APPLICABLE -> notApplicable.orElseThrow(() -> new InvalidInputException(
                    "This version of the template does not offer \"not applicable\"."));
        };
    }

    /**
     * The word a document writes for an answer: {@link #word}, and in words — "Not applicable" — for a
     * "not applicable" this version does not offer. Only a draft holds one — a carried line awaiting
     * confirmation — and a draft still renders.
     */
    public String written(ChecklistAnswer answer) {
        return answer == ChecklistAnswer.NOT_APPLICABLE && !offersNotApplicable() ? "Not applicable" : word(answer);
    }

    /**
     * The answer a cell's word stands for, compared as the words are distinguished above; empty
     * when it is none of them.
     */
    public Optional<ChecklistAnswer> answerOf(String word) {
        if (word == null) {
            return Optional.empty();
        }
        if (same(word, yes)) {
            return Optional.of(ChecklistAnswer.YES);
        }
        if (same(word, no)) {
            return Optional.of(ChecklistAnswer.NO);
        }
        return notApplicable.filter(mapped -> same(word, mapped)).map(mapped -> ChecklistAnswer.NOT_APPLICABLE);
    }

    /**
     * Case and spacing aside, because a spreadsheet's list validation compares that way: two words
     * it would accept for one another cannot be two answers.
     */
    private static boolean same(String left, String right) {
        return ChecklistText.normalize(left).toLowerCase(Locale.ROOT)
                .equals(ChecklistText.normalize(right).toLowerCase(Locale.ROOT));
    }
}

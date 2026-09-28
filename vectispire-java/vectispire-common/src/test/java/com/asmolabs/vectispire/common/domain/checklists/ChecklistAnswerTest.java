package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("an answer, its comment and the template's words for it")
class ChecklistAnswerTest {

    private static final AnswerWords TWO = AnswerWords.of("Done", "Not done");
    private static final AnswerWords THREE = new AnswerWords("Done", "Not done", Optional.of("Out of scope"));

    @Test
    @DisplayName("a no and a not applicable need their comment; a yes does not")
    void comments() {
        assertThat(GivenAnswer.of(ChecklistAnswer.YES, null, TWO).comment()).isEmpty();
        assertThat(GivenAnswer.of(ChecklistAnswer.NO, " We have no directory yet. ", TWO).comment())
                .contains("We have no directory yet.");

        assertThatThrownBy(() -> GivenAnswer.of(ChecklistAnswer.NO, "  ", TWO))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("needs a comment");
        assertThatThrownBy(() -> GivenAnswer.of(ChecklistAnswer.NOT_APPLICABLE, null, THREE))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("needs a comment");
    }

    @Test
    @DisplayName("not applicable only where the version offers it")
    void notApplicableOffered() {
        assertThatThrownBy(() -> GivenAnswer.of(ChecklistAnswer.NOT_APPLICABLE, "No such component.", TWO))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("does not offer");
        assertThat(GivenAnswer.of(ChecklistAnswer.NOT_APPLICABLE, "No such component.", THREE).value())
                .isEqualTo(ChecklistAnswer.NOT_APPLICABLE);
        assertThatThrownBy(() -> TWO.word(ChecklistAnswer.NOT_APPLICABLE)).hasMessageContaining("does not offer");
    }

    @Test
    @DisplayName("a comment is bounded before the write")
    void bounded() {
        assertThatThrownBy(() -> GivenAnswer.of(ChecklistAnswer.NO, "x".repeat(GivenAnswer.MAX_COMMENT + 1), TWO))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("longer than " + GivenAnswer.MAX_COMMENT);
    }

    @Test
    @DisplayName("the words are written back as mapped, and read back whatever their case and spacing")
    void words() {
        assertThat(THREE.word(ChecklistAnswer.YES)).isEqualTo("Done");
        assertThat(THREE.word(ChecklistAnswer.NOT_APPLICABLE)).isEqualTo("Out of scope");
        assertThat(THREE.answerOf(" not  DONE ")).contains(ChecklistAnswer.NO);
        assertThat(THREE.answerOf("out of scope")).contains(ChecklistAnswer.NOT_APPLICABLE);
        assertThat(TWO.answerOf("Out of scope")).isEmpty();
        assertThat(TWO.offersNotApplicable()).isFalse();
    }

    @Test
    @DisplayName("two answers cannot share a word, since the workbook could not be read back")
    void distinct() {
        assertThatThrownBy(() -> AnswerWords.of("Yes", " yes"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("same word");
        assertThatThrownBy(() -> new AnswerWords("Yes", "No", Optional.of("NO")))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("already mapped");
        assertThatThrownBy(() -> AnswerWords.of("", "No")).hasMessageContaining("The word for yes is required");
    }

    @Test
    @DisplayName("the answer's wire name is parsed, and anything else refused in words")
    void parse() {
        assertThat(ChecklistAnswer.parse(" Not_Applicable ")).isEqualTo(ChecklistAnswer.NOT_APPLICABLE);
        assertThatThrownBy(() -> ChecklistAnswer.parse("maybe"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("An answer is one of yes, no, not_applicable; \"maybe\" is not one of them.");
    }
}

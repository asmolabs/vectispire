package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("who wrote an answer")
class AnswerAuthorTest {

    @Test
    @DisplayName("only the stored kind system is Vectispire's; an unknown or absent kind is read as a person's")
    void theKindDecides() {
        assertThat(AnswerAuthor.isSystem("system")).isTrue();
        assertThat(AnswerAuthor.isSystem("person")).isFalse();
        // Read as a person's, an answer is never replaced by the scans: the safe way to err.
        assertThat(AnswerAuthor.isSystem("robot")).isFalse();
        assertThat(AnswerAuthor.isSystem(null)).isFalse();
        assertThat(AnswerAuthor.isSystem("Vectispire")).as("a name is not a kind").isFalse();
    }
}

package com.asmolabs.vectispire.common.domain.teams;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("what a team may be called, and own")
class TeamRulesTest {

    @Test
    @DisplayName("a name is trimmed, because the screen reads it trimmed")
    void namesAreTrimmed() {
        // "Backend " and "Backend" are one team to everybody looking at the list. Storing both
        // would let the unique constraint disagree with what an administrator sees.
        assertThat(TeamRules.validateName("  Backend  ")).isEqualTo("Backend");
    }

    @Test
    @DisplayName("a name of whitespace is refused, not stored as empty")
    void blankNamesAreRefused() {
        assertThatThrownBy(() -> TeamRules.validateName("   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("required");
        assertThatThrownBy(() -> TeamRules.validateName(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("an over-long name is refused rather than truncated")
    void longNamesAreRefused() {
        // Truncating would silently create a second team whose name is a prefix of another's,
        // which is the one thing the unique name exists to prevent.
        assertThatThrownBy(() -> TeamRules.validateName("x".repeat(TeamRules.MAX_NAME_LENGTH + 1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(TeamRules.validateName("x".repeat(TeamRules.MAX_NAME_LENGTH)))
                .hasSize(TeamRules.MAX_NAME_LENGTH);
    }

    @Test
    @DisplayName("a description of spaces is no description")
    void blankDescriptionsBecomeNull() {
        assertThat(TeamRules.trimDescription("   ")).isNull();
        assertThat(TeamRules.trimDescription(null)).isNull();
        assertThat(TeamRules.trimDescription(" the platform team ")).isEqualTo("the platform team");
    }

    @Test
    @DisplayName("a description is truncated, because it decides nothing")
    void longDescriptionsAreTruncated() {
        // The opposite of the name: nothing keys on it, so losing its tail costs a sentence,
        // while refusing the save would cost the administrator their whole edit.
        assertThat(TeamRules.trimDescription("y".repeat(TeamRules.MAX_DESCRIPTION_LENGTH + 50)))
                .hasSize(TeamRules.MAX_DESCRIPTION_LENGTH);
    }

    @Test
    @DisplayName("an unknown target kind is refused, never stored")
    void unknownKindsAreRefused() {
        assertThat(TeamRules.validateTargetKind("Repository")).isEqualTo("repository");
        assertThat(TeamRules.validateTargetKind(" container ")).isEqualTo("container");

        // Stored, it would resolve to no target at all: an assignment the screen displays and
        // that grants nothing. An error message is the kinder failure.
        assertThatThrownBy(() -> TeamRules.validateTargetKind("cluster"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unknown target kind");
        assertThatThrownBy(() -> TeamRules.validateTargetKind(null)).isInstanceOf(IllegalArgumentException.class);
    }
}

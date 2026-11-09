package com.asmolabs.vectispire.common.domain.agents;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("the agent contract")
class AgentContractTest {

    @Test
    @DisplayName("serves its own contract and every one down to the oldest it keeps")
    void servesTheRange() {
        for (int version = AgentContract.OLDEST_SERVED; version <= AgentContract.CURRENT; version++) {
            assertThat(AgentContract.isCompatible(String.valueOf(version))).as("contract %d", version).isTrue();
        }
        assertThat(AgentContract.isCompatible(AgentContract.VERSION)).isTrue();
        assertThat(AgentContract.isCompatible(" " + AgentContract.VERSION + " ")).isTrue();
    }

    @Test
    @DisplayName("refuses a contract below the range, whose form was deleted, and one above it")
    void refusesOutsideTheRange() {
        // Below: the code that spoke it is gone. Above: an agent newer than its control plane, the
        // order 0043 §2 does not support — this side cannot know what that number asks.
        assertThat(AgentContract.isCompatible(String.valueOf(AgentContract.OLDEST_SERVED - 1))).isFalse();
        assertThat(AgentContract.isCompatible(String.valueOf(AgentContract.CURRENT + 1))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "1.1", "01", "+1", "-1", "0", "one", "99999999999"})
    @DisplayName("refuses what is no contract number, rather than reading one into it")
    void refusesWhatIsNotANumber(String announced) {
        assertThat(AgentContract.isCompatible(announced)).isFalse();
        assertThat(AgentContract.parse(announced)).isEmpty();
    }

    @Test
    @DisplayName("refuses an agent that announces nothing")
    void refusesNothing() {
        assertThat(AgentContract.isCompatible(null)).isFalse();
    }

    @Test
    @DisplayName("the range is never empty, and the release agents announce 1 is in it")
    void theRangeHoldsTheReleasedAgent() {
        // Every agent released so far — 0.11.2 included, the one the `previous-agent` job runs —
        // announces "1". Raising OLDEST_SERVED past it is the second step of a change, made a release
        // after the first and never in the commit that moves CURRENT; that release edits this line.
        assertThat(AgentContract.OLDEST_SERVED).isBetween(1, AgentContract.CURRENT);
        assertThat(AgentContract.isCompatible("1")).isTrue();
    }

    @Test
    @DisplayName("tells an operator which side to upgrade")
    void namesTheSideToUpgrade() {
        assertThat(AgentContract.remedy(String.valueOf(AgentContract.CURRENT + 1)))
                .isEqualTo("Upgrade the control plane first, then its agents.");
        assertThat(AgentContract.remedy("0")).isEqualTo("Update the agent.");
        assertThat(AgentContract.remedy(null)).isEqualTo("Update the agent.");
    }
}

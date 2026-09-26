package com.asmolabs.vectispire.common.domain.agents;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.OptionalInt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("how many scans an agent runs at once")
class AgentConcurrencyTest {

    @Test
    @DisplayName("a stored value outside the bound is clamped, and nothing reads as zero")
    void clampsWhatIsStored() {
        // Zero read as zero would be a paused agent nobody paused: it claims nothing, and the
        // screen says it is enabled.
        assertThat(AgentConcurrency.effective(null)).isEqualTo(1);
        assertThat(AgentConcurrency.effective(0)).isEqualTo(1);
        assertThat(AgentConcurrency.effective(-3)).isEqualTo(1);
        assertThat(AgentConcurrency.effective(4)).isEqualTo(4);
        assertThat(AgentConcurrency.effective(16)).isEqualTo(16);
        assertThat(AgentConcurrency.effective(17)).isEqualTo(16);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 17, 1000})
    @DisplayName("an administrator asking outside the bound is told so")
    void refusesOutsideTheBound(int requested) {
        assertThat(AgentConcurrency.refusal(requested)).isPresent();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 16})
    void acceptsTheBoundItself(int requested) {
        assertThat(AgentConcurrency.refusal(requested)).isEmpty();
    }

    @Test
    @DisplayName("an absent or unreadable header leaves the agent with what it knew")
    void readsTheHeader() {
        assertThat(AgentConcurrency.parse(null)).isEmpty();
        assertThat(AgentConcurrency.parse(" ")).isEmpty();
        assertThat(AgentConcurrency.parse("many")).isEmpty();
        assertThat(AgentConcurrency.parse(" 3 ")).isEqualTo(OptionalInt.of(3));
        // A control plane that sends more than the bound does not buy more than the bound here.
        assertThat(AgentConcurrency.parse("64")).isEqualTo(OptionalInt.of(16));
    }
}

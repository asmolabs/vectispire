package com.asmolabs.vectispire.common.domain.agents;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("agent routing")
class AgentLabelsTest {

    @Test
    @DisplayName("normalizes case and whitespace, so two screens mean the same thing")
    void normalizesLabels() {
        // "Production" and "production" typed six months apart must match, or a scan waits
        // indefinitely for an agent that is right there and nothing explains why.
        assertThat(AgentLabels.parse(" Production , CUSTOMER-repos ")).containsExactly("production", "customer-repos");
    }

    @Test
    @DisplayName("commas alone are not labels")
    void discardsEmptyEntries() {
        // Without the filter an empty string enters the list and satisfies an empty
        // requirement.
        assertThat(AgentLabels.parse(",,  ,")).isEmpty();
        assertThat(AgentLabels.parse(null)).isEmpty();
    }

    @ParameterizedTest(name = "a requirement of [{0}] means none at all")
    @ValueSource(strings = {"", "   ", ",", ",,", "production,staging"})
    void unsatisfiableRequirementBecomesNone(String raw) {
        // **The case that would silently jam a queue.** A cleared field means "no requirement
        // any more"; storing what is left gives a requirement no agent ever satisfies, and the
        // scan waits forever with nothing saying why.
        //
        // A comma-bearing value is the same failure with a subtler cause: agent labels are
        // split on the comma, so no agent can carry a label containing one. Such a requirement
        // is unsatisfiable by construction — a permanent block, stored.
        assertThat(AgentLabels.normalizeRequirement(raw)).isEmpty();
    }

    @Test
    @DisplayName("a single label is kept, normalized")
    void singleLabelIsKept() {
        assertThat(AgentLabels.normalizeRequirement("  Production ")).contains("production");
    }

    @Test
    @DisplayName("a scan with no requirement goes to anyone")
    void openOnTheScanSide() {
        // The previous behaviour. Requiring a label retroactively would stop every existing
        // queue on the first deployment.
        assertThat(AgentLabels.accepts(List.of(), Optional.empty())).isTrue();
        assertThat(AgentLabels.accepts(List.of("production"), Optional.empty())).isTrue();
    }

    @Test
    @DisplayName("an agent with no label takes only work with no requirement")
    void closedOnTheAgentSide() {
        // The reverse — "no label means all of them" — is the seductive reading, and it makes
        // the requirement inoperative at the first agent registered without thinking about it.
        assertThat(AgentLabels.accepts(List.of(), Optional.of("production"))).isFalse();
    }

    @Test
    @DisplayName("matches an agent carrying the required capability")
    void matchesOnCapability() {
        assertThat(AgentLabels.accepts(List.of("staging", "production"), Optional.of("production"))).isTrue();
        assertThat(AgentLabels.accepts(List.of("staging"), Optional.of("production"))).isFalse();
    }

    @Test
    @DisplayName("the contract version is compared strictly")
    void contractIsStrict() {
        // A looser comparison looks welcoming and moves the question elsewhere: it would then
        // be necessary to decide, for every field added, whether an agent that ignores it is
        // still correct.
        assertThat(AgentContract.isCompatible(AgentContract.VERSION)).isTrue();
        assertThat(AgentContract.isCompatible(" 1 ")).isTrue();
        assertThat(AgentContract.isCompatible("1.1")).isFalse();
        assertThat(AgentContract.isCompatible("2")).isFalse();
        assertThat(AgentContract.isCompatible(null)).isFalse();
    }
}

package com.asmolabs.vectispire.core.access.web.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("an integration key's attribution")
class IntegrationAttributionTest {

    @Test
    @DisplayName("names the account and the key")
    void namesBoth() {
        assertThat(VectispirePrincipal.attribution("alice", "ci")).isEqualTo("alice (API key ci)");
    }

    @Test
    @DisplayName("fits the actor column: the key's name gives way first, then the account's")
    void fitsTheColumn() {
        String shortened = VectispirePrincipal.attribution("a".repeat(200), "k".repeat(100));
        assertThat(shortened).hasSize(VectispirePrincipal.ACTOR_WIDTH).startsWith("a".repeat(200) + " (API key k").endsWith("…)");

        String longest = VectispirePrincipal.attribution("a".repeat(255), "ci");
        assertThat(longest).hasSizeLessThanOrEqualTo(VectispirePrincipal.ACTOR_WIDTH).endsWith(" (API key …)");
    }
}

package com.asmolabs.vectispire.common.domain.apikeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Period;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("API keys")
class ApiKeysTest {

    @Nested
    @DisplayName("generation")
    class Generation {

        @Test
        @DisplayName("produces a prefixed key and the stored prefix")
        void producesTheExpectedShape() {
            ApiKeys.IssuedKey issued = ApiKeys.generate();

            assertThat(issued.fullKey()).matches("^zsk_[A-Za-z0-9_-]{43}$");
            assertThat(issued.prefix()).isEqualTo(issued.fullKey().substring(0, ApiKeys.PREFIX_LENGTH));
            assertThat(issued.prefix()).hasSize(12).startsWith("zsk_");
        }

        @Test
        @DisplayName("does not repeat a key")
        void doesNotRepeat() {
            Set<String> keys = new HashSet<>();
            IntStream.range(0, 200).forEach(i -> keys.add(ApiKeys.generate().fullKey()));

            assertThat(keys).hasSize(200);
        }
    }

    @Nested
    @DisplayName("scopes")
    class Scopes {

        @Test
        @DisplayName("takes the broad defaults when nothing is requested")
        void defaultsAreBroad() {
            // A form whose defaults break the caller's pipeline teaches them to tick
            // everything. Narrowing is offered, not imposed.
            assertThat(ApiKeys.normalizeScopes(null)).isEqualTo(ApiKeyScope.defaults());
            assertThat(ApiKeys.normalizeScopes(List.of())).isEqualTo(ApiKeyScope.defaults());
        }

        @Test
        @DisplayName("never grants agent implicitly")
        void agentIsNeverImplicit() {
            // It is the scope that lets a holder execute work on Vectispire's behalf.
            assertThat(ApiKeys.normalizeScopes(null)).doesNotContain(ApiKeyScope.AGENT);
        }

        @Test
        @DisplayName("emits in declaration order, so two identical keys store the same string")
        void orderIsStable() {
            assertThat(ApiKeys.normalizeScopes(List.of("export", "read")))
                    .isEqualTo(ApiKeys.normalizeScopes(List.of("read", "export")))
                    .containsExactly(ApiKeyScope.READ, ApiKeyScope.EXPORT);
        }

        @Test
        @DisplayName("refuses an unknown scope rather than ignoring it")
        void refusesUnknownScopes() {
            // A caller who misspells `agent` and gets a working key will believe it was
            // granted.
            assertThatThrownBy(() -> ApiKeys.normalizeScopes(List.of("read", "admin")))
                    .isInstanceOf(InvalidApiKeyException.class)
                    .hasMessageContaining("admin");
        }

        @Test
        @DisplayName("refuses a list that is only blanks")
        void refusesEmptyAfterCleaning() {
            assertThatThrownBy(() -> ApiKeys.normalizeScopes(List.of("  ", "")))
                    .hasMessageContaining("could do nothing");
        }
    }

    @Nested
    @DisplayName("lifetime")
    class Lifetime {

        @Test
        @DisplayName("accepts nothing, or a plausible number of days")
        void acceptsReasonableLifetimes() {
            assertThat(ApiKeys.normalizeLifetime(null)).isEmpty();
            assertThat(ApiKeys.normalizeLifetime(90)).contains(Period.ofDays(90));
        }

        @ParameterizedTest(name = "refuses {0} days")
        @ValueSource(ints = {0, -1, 3651})
        void refusesImplausibleLifetimes(int days) {
            assertThatThrownBy(() -> ApiKeys.normalizeLifetime(days)).isInstanceOf(InvalidApiKeyException.class);
        }
    }
}

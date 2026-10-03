package com.asmolabs.vectispire.common.domain.net;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The rule itself is pinned through the collector's CA ({@code CollectorCaTest}), which delegates to it; this
 * pins that each field's refusals speak of their own field — a forge's CA refused in the SIEM's words would
 * send the administrator to the wrong screen.
 */
@DisplayName("a pinned CA's refusals name their own field")
class PinnedCaTest {

    private static final PinnedCa.Subject FORGE = new PinnedCa.Subject("The forge's CA", "the forge");

    @Test
    void refusalsNameTheField() {
        assertThatThrownBy(() -> PinnedCa.parse(" ", Instant.now(), FORGE))
                .isInstanceOf(InvalidInputException.class).hasMessage("The forge's CA is empty.");
        assertThatThrownBy(() -> PinnedCa.parse("hello", Instant.now(), FORGE))
                .hasMessageStartingWith("The forge's CA holds no certificate");
        assertThatThrownBy(() -> PinnedCa.parse("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
                        Instant.now(), FORGE))
                .hasMessage("The forge's CA is not a readable PEM certificate.");
    }
}

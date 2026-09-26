package com.asmolabs.vectispire.common.domain.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a value written into one log line")
class LogTextTest {

    @Test
    @DisplayName("a line break, a separator or an escape sequence is written visibly, never as itself")
    void controlCharactersAreVisible() {
        String forged = "SEC-1\r\n2026-09-26 INFO  admin signed in\u2028\u001b[2J";

        String logged = LogText.of(forged);

        assertThat(logged)
                .doesNotContain("\n", "\r", "\u2028", "\u001b")
                .isEqualTo("SEC-1\\u000d\\u000a2026-09-26 INFO  admin signed in\\u2028\\u001b[2J");
    }

    @Test
    @DisplayName("an ordinary key is unchanged, a huge one is cut and says how long it was")
    void ordinaryAndHuge() {
        assertThat(LogText.of("SEC-4242")).isEqualTo("SEC-4242");
        assertThat(LogText.of(null)).isEqualTo("null");
        assertThat(LogText.of("x".repeat(5_000))).hasSizeLessThan(LogText.MAX + 32).endsWith("(5000 chars)");
    }
}

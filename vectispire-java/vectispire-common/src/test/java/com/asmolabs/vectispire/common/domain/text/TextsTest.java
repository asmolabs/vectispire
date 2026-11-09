package com.asmolabs.vectispire.common.domain.text;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a blank value read as absent")
class TextsTest {

    @Test
    @DisplayName("null and blank are absent, anything else is kept as written")
    void blankIsAbsent() {
        assertThat(Texts.blankToNull(null)).isNull();
        assertThat(Texts.blankToNull(" \t")).isNull();
        assertThat(Texts.blankToNull(" kept ")).isEqualTo(" kept ");
    }

    @Test
    @DisplayName("each trimming spelling loses the whitespace it always lost, and no other")
    void theTwoTrimsDiffer() {
        // U+2003 is whitespace to `strip` and not to `trim`; U+0001 the reverse. A stored value
        // trimmed one way and compared after the other would differ by exactly these.
        assertThat(Texts.strippedOrNull(" id\u0001 ")).isEqualTo("id\u0001");
        assertThat(Texts.trimmedOrNull(" id\u0001 ")).isEqualTo(" id");
        assertThat(Texts.strippedOrNull("  ")).isNull();
        assertThat(Texts.trimmedOrNull(null)).isNull();
    }
}

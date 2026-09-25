package com.asmolabs.vectispire.common.domain.text;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a string bounded by its column")
class BoundedTextTest {

    @Test
    @DisplayName("a required value is trimmed, and refused when blank or one character too long")
    void required() {
        assertThat(BoundedText.required("  alpha  ", 5, "The name")).isEqualTo("alpha");
        assertThatThrownBy(() -> BoundedText.required("   ", 5, "The name"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The name is required.");
        assertThatThrownBy(() -> BoundedText.required("abcdef", 5, "The name"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The name is longer than 5 characters.");
    }

    @Test
    @DisplayName("an optional value is null when blank, and refused rather than cut when too long")
    void optional() {
        assertThat(BoundedText.optional(null, 5, "The label")).isNull();
        assertThat(BoundedText.optional("  ", 5, "The label")).isNull();
        assertThat(BoundedText.optional("abcde", 5, "The label")).isEqualTo("abcde");
        assertThatThrownBy(() -> BoundedText.optional("abcdef", 5, "The label"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a value checked as given keeps its whitespace")
    void within() {
        assertThat(BoundedText.within(" s3cret ", 8, "The secret")).isEqualTo(" s3cret ");
        assertThatThrownBy(() -> BoundedText.within(" s3cret  ", 8, "The secret"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a clipped value fits, and never ends on half a surrogate pair")
    void clip() {
        assertThat(BoundedText.clip(null, 3)).isNull();
        assertThat(BoundedText.clip("abc", 3)).isEqualTo("abc");
        assertThat(BoundedText.clip("abcdef", 3)).isEqualTo("abc");

        // "ab" then U+1F600, two units: cutting at three would keep its high half alone.
        String emoji = "ab😀";
        assertThat(BoundedText.clip(emoji, 3)).isEqualTo("ab");
        assertThat(BoundedText.clip(emoji, 4)).isEqualTo(emoji);
    }
}

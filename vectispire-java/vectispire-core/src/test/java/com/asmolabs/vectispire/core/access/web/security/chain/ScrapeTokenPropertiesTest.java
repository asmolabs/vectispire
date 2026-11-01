package com.asmolabs.vectispire.core.access.web.security.chain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("the metrics scrape token's configuration")
class ScrapeTokenPropertiesTest {

    private static final String LONG_ENOUGH = "a-scrape-token-of-thirty-two-chars";

    @Test
    @DisplayName("is refused at start when shorter than the floor, from the value or from the file")
    void aShortTokenStopsTheStart(@TempDir Path dir) throws Exception {
        assertThatThrownBy(() -> new ScrapeTokenProperties(Optional.of("short"), Optional.empty()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least 32");

        Path file = Files.writeString(dir.resolve("token"), "short\n");
        assertThatThrownBy(() -> new ScrapeTokenProperties(Optional.empty(), Optional.of(file.toString())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least 32");
    }

    @Test
    @DisplayName("reads the file over the value, trimmed of the newline every way of writing it adds")
    void theFileWins(@TempDir Path dir) throws Exception {
        Path file = Files.writeString(dir.resolve("token"), LONG_ENOUGH + "-from-file\n");

        ScrapeTokenProperties properties =
                new ScrapeTokenProperties(Optional.of(LONG_ENOUGH), Optional.of(file.toString()));

        assertThat(properties.token()).contains(LONG_ENOUGH + "-from-file");
    }

    @Test
    @DisplayName("is absent when neither is set, or the value is blank — the page is then an administrator's only")
    void unsetIsAbsent() {
        assertThat(new ScrapeTokenProperties(Optional.empty(), Optional.empty()).token()).isEmpty();
        assertThat(new ScrapeTokenProperties(Optional.of(""), Optional.of(" ")).token()).isEmpty();
        assertThat(new ScrapeTokenProperties(null, null).token()).isEmpty();
    }
}

package com.asmolabs.vectispire.core.access.web.scim;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("the SCIM token's length")
class ScimPropertiesTest {

    private static final String LONG_ENOUGH = "x".repeat(ScimProperties.MIN_TOKEN_LENGTH);
    private static final String SHORT = "x".repeat(ScimProperties.MIN_TOKEN_LENGTH - 1);

    @Test
    @DisplayName("a short token is refused at start while SCIM is enabled")
    void aShortTokenIsRefused() {
        assertThatThrownBy(() -> new ScimProperties(true, Optional.of(SHORT), Optional.empty()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least " + ScimProperties.MIN_TOKEN_LENGTH);
        assertThatCode(() -> new ScimProperties(true, Optional.of(LONG_ENOUGH), Optional.empty()))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a short token read from a file is refused too")
    void aShortFileIsRefused(@TempDir Path secrets) throws Exception {
        Path file = Files.writeString(secrets.resolve("scim"), SHORT);
        assertThatThrownBy(() -> new ScimProperties(true, Optional.empty(), Optional.of(file.toString())))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("SCIM switched off accepts nothing, so a token left behind does not stop the start")
    void disabledIsNotChecked() {
        assertThatCode(() -> new ScimProperties(false, Optional.of(SHORT), Optional.empty())).doesNotThrowAnyException();
    }
}

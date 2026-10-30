package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the host name in a worker's identity")
class LocalHostTest {

    @Test
    @DisplayName("is cut to the length its column holds, and kept whole below it")
    void isCutToItsColumn() {
        String whole = LocalHost.name();

        assertThat(whole).isNotBlank();
        assertThat(LocalHost.name(1)).isEqualTo(whole.substring(0, 1));
        assertThat(LocalHost.name(whole.length() + 10)).isEqualTo(whole);
    }
}

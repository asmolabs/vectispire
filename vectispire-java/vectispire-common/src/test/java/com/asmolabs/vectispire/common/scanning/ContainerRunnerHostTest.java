package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ContainerRunner Daemon Host Resolution")
class ContainerRunnerHostTest {

    @Test
    @DisplayName("resolves host without raising exceptions")
    void resolvesDaemonHostSafely() {
        String host = ContainerRunner.resolveDockerHost();
        // May be null or a unix/tcp socket string depending on machine environment
        if (host != null) {
            assertThat(host).isNotBlank();
        }
    }
}

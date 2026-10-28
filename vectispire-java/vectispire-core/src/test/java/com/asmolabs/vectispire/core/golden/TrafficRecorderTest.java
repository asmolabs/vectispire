package com.asmolabs.vectispire.core.golden;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the traffic recorder")
class TrafficRecorderTest {

    @Test
    @DisplayName("keeps a PEM answer as text, where its key can be hidden, and a document as a binary sidecar")
    void aPemIsText() {
        assertThat(TrafficRecorder.isTextual("application/x-pem-file;charset=utf-8")).isTrue();
        assertThat(TrafficRecorder.isTextual("application/x-pem-file")).isTrue();
        assertThat(TrafficRecorder.isTextual("application/json")).isTrue();
        assertThat(TrafficRecorder.isTextual("application/pdf")).isFalse();
        assertThat(TrafficRecorder.isTextual("application/zip")).isFalse();
        assertThat(TrafficRecorder.isTextual("application/octet-stream")).isFalse();
    }
}

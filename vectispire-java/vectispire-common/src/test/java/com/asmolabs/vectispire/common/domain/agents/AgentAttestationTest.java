package com.asmolabs.vectispire.common.domain.agents;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Agent Scan Attestation")
class AgentAttestationTest {

    @Test
    @DisplayName("signs and verifies agent scan payload")
    void signsAndVerifiesScanPayload() {
        long scanId = 12345L;
        String agentId = "agent-node-01";
        byte[] payload = "{\"sbom\": \"...\", \"cves\": \"...\"}".getBytes(StandardCharsets.UTF_8);
        String secret = "super-secret-agent-key";

        String signature = AgentAttestation.sign(scanId, agentId, payload, secret);
        assertThat(signature).isNotNull().hasSize(64); // 256 bits = 64 hex chars

        boolean valid = AgentAttestation.verify(scanId, agentId, payload, secret, signature);
        assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("rejects signature when payload is altered")
    void rejectsAlteredPayload() {
        long scanId = 12345L;
        String agentId = "agent-node-01";
        byte[] payload = "{\"sbom\": \"clean\"}".getBytes(StandardCharsets.UTF_8);
        byte[] tampered = "{\"sbom\": \"tampered\"}".getBytes(StandardCharsets.UTF_8);
        String secret = "super-secret-agent-key";

        String signature = AgentAttestation.sign(scanId, agentId, payload, secret);

        boolean valid = AgentAttestation.verify(scanId, agentId, tampered, secret, signature);
        assertThat(valid).isFalse();
    }

    @Test
    @DisplayName("rejects signature when secret is incorrect")
    void rejectsWrongSecret() {
        long scanId = 12345L;
        String agentId = "agent-node-01";
        byte[] payload = "{\"sbom\": \"clean\"}".getBytes(StandardCharsets.UTF_8);

        String signature = AgentAttestation.sign(scanId, agentId, payload, "correct-secret");

        boolean valid = AgentAttestation.verify(scanId, agentId, payload, "wrong-secret", signature);
        assertThat(valid).isFalse();
    }
}

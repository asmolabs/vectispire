package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SealingKeyAttestation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

/**
 * The agent's half of decision 0031: it signs the sealing key it makes at start, and reads the
 * control plane's answer as what the operator has to do.
 */
@DisplayName("the agent announces its sealing key, signed")
class AgentSealingKeyAnnouncementTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final UUID AGENT = UUID.fromString("5d0c9d2e-2f4b-4a53-9a39-2c7f0b8e6a11");
    private static final long GENERATION = 1_790_380_800_000L;
    private static final String SEALING = "/api/v1/agent/sealing-key";

    private final ResultAttestation.KeyPair signing = ResultAttestation.generate();
    private final SealedEnvelope.KeyPair keyPair = new SealedEnvelope().generateKeyPair();

    private AgentHttp http;
    private AgentProtocol protocol;

    @BeforeEach
    void wire() {
        http = mock(AgentHttp.class);
        protocol = new AgentProtocol(http, JSON, keyPair, signing.privateKey(), GENERATION);
        answer("/api/v1/agent/hello", 200,
                "{\"id\":\"" + AGENT + "\",\"name\":\"edge\",\"contractVersion\":\"1\",\"maxConcurrent\":1,"
                        + "\"credentialsMode\":\"delegated\"}");
    }

    private void answer(String path, int status, String body) {
        when(http.call(eq(path), anyString(), any(), any())).thenReturn(new AgentHttp.Response(status, parse(body)));
    }

    private static JsonNode parse(String body) {
        try {
            return body == null || body.isEmpty() ? JSON.nullNode() : JSON.readTree(body);
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    private void hello() {
        protocol.hello(new AgentProtocol.Description("host", "linux", "1", "docker"));
    }

    @Test
    @DisplayName("the key, its generation and a signature by the pinned key over this agent's id")
    @SuppressWarnings("unchecked")
    void theAnnouncementIsSignedForThisAgent() {
        answer(SEALING, 204, "");
        hello();

        assertThat(protocol.announceSealingKey()).isEqualTo(AgentProtocol.SealingKeyOutcome.ACCEPTED);

        ArgumentCaptor<Object> body = ArgumentCaptor.forClass(Object.class);
        verify(http).call(eq(SEALING), eq("POST"), body.capture(), any());
        Map<String, Object> sent = (Map<String, Object>) body.getValue();
        assertThat(sent).containsEntry("public_key", keyPair.publicKey()).containsEntry("generation", GENERATION);
        assertThat(SealingKeyAttestation.verify(
                        signing.publicKey(), AGENT, GENERATION, keyPair.publicKey(), (String) sent.get("signature")))
                .isTrue();
    }

    /** Each answer is a different step for the operator, and none of them stops the agent. */
    @ParameterizedTest
    @CsvSource({"204, ACCEPTED", "404, NOT_SUPPORTED", "412, NOT_PINNED", "403, REFUSED", "409, STALE"})
    @DisplayName("each answer is read as its own outcome, none as an exception")
    void eachAnswerIsAnOutcome(int status, AgentProtocol.SealingKeyOutcome expected) {
        answer(SEALING, status, status == 204 ? "" : "{\"detail\":\"said by the control plane\"}");
        hello();

        assertThat(protocol.announceSealingKey()).isEqualTo(expected);
    }

    @Test
    @DisplayName("a refused API key is still the fatal error it is everywhere else")
    void aRefusedApiKeyIsFatal() {
        answer(SEALING, 401, "{\"detail\":\"API key refused.\"}");
        hello();

        assertThatThrownBy(() -> protocol.announceSealingKey()).isInstanceOf(AgentProtocol.UnauthorizedException.class);
    }

    @Test
    @DisplayName("with no signing key configured, or before the hello named the agent, nothing is sent")
    void nothingToSignWithSendsNothing() {
        AgentProtocol unsigned = new AgentProtocol(http, JSON, keyPair, "", GENERATION);
        unsigned.hello(new AgentProtocol.Description("host", "linux", "1", "docker"));
        assertThat(unsigned.announceSealingKey()).isEqualTo(AgentProtocol.SealingKeyOutcome.UNSIGNABLE);

        AgentProtocol beforeHello = new AgentProtocol(http, JSON, keyPair, signing.privateKey(), GENERATION);
        assertThat(beforeHello.announceSealingKey()).isEqualTo(AgentProtocol.SealingKeyOutcome.UNSIGNABLE);

        verify(http, never()).call(eq(SEALING), anyString(), any(), any());
    }

    /**
     * The second half of the upgrade matrix: an agent of this version against an older control plane.
     * Its hello still carries the unsigned key such a control plane seals for, and the signed route's
     * 404 is read as "not supported" rather than as a failure.
     */
    @Test
    @DisplayName("the hello still carries the key, unsigned, for a control plane that predates the signed one")
    @SuppressWarnings("unchecked")
    void anOlderControlPlaneStillSealsForTheHello() {
        answer(SEALING, 404, "{\"detail\":\"No endpoint.\"}");
        hello();

        ArgumentCaptor<Object> body = ArgumentCaptor.forClass(Object.class);
        verify(http).call(eq("/api/v1/agent/hello"), eq("POST"), body.capture(), any());
        assertThat((Map<String, Object>) body.getValue()).containsEntry("sealing_public_key", keyPair.publicKey());
        assertThat(protocol.announceSealingKey()).isEqualTo(AgentProtocol.SealingKeyOutcome.NOT_SUPPORTED);
    }

    @Test
    @DisplayName("the runner announces the key after the hello of a delegated agent, and not for a local one")
    void theRunnerAnnouncesForADelegatedAgentOnly() {
        answer(SEALING, 204, "");
        AgentProtocol.Description description = new AgentProtocol.Description("host", "linux", "1", "docker");

        AgentRunner.announce(protocol, description);
        verify(http, times(1)).call(eq(SEALING), eq("POST"), any(), any());

        answer("/api/v1/agent/hello", 200,
                "{\"id\":\"" + AGENT + "\",\"name\":\"edge\",\"contractVersion\":\"1\",\"maxConcurrent\":1,"
                        + "\"credentialsMode\":\"local\"}");
        AgentRunner.announce(protocol, description);
        verify(http, times(1)).call(eq(SEALING), eq("POST"), any(), any());
    }

    @Test
    @DisplayName("whatever the control plane answers, the runner carries on — except a refused API key")
    void theRunnerNeverStopsOnTheAnswer() {
        answer(SEALING, 500, "{\"detail\":\"down\"}");
        hello();
        assertThat(AgentRunner.announceSealingKey(protocol)).isEqualTo(AgentProtocol.SealingKeyOutcome.UNSIGNABLE);

        answer(SEALING, 403, "{\"detail\":\"does not verify\"}");
        assertThat(AgentRunner.announceSealingKey(protocol)).isEqualTo(AgentProtocol.SealingKeyOutcome.REFUSED);

        answer(SEALING, 401, "{\"detail\":\"API key refused.\"}");
        assertThatThrownBy(() -> AgentRunner.announceSealingKey(protocol))
                .isInstanceOf(AgentProtocol.UnauthorizedException.class);
    }

    /**
     * A withheld credential after an accepted announcement means the control plane forgot the key —
     * a reset, a signing key pinned anew. The agent announces once more, so the next claim takes the
     * scan; after a refusal it does not, or every claim would add a refusal to the audit log.
     */
    @Test
    @DisplayName("a withheld credential makes an accepted agent announce again, and a refused one stay quiet")
    void aWithheldCredentialAnnouncesAgainOnlyAfterAnAcceptance() {
        answer("/api/v1/agent/jobs?wait=1", 412, "{\"detail\":\"announced none that verified\"}");
        answer(SEALING, 204, "");
        hello();
        protocol.announceSealingKey();

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1))).hasMessageContaining("announced none that verified");
        verify(http, times(2)).call(eq(SEALING), eq("POST"), any(), any());

        answer(SEALING, 403, "{\"detail\":\"does not verify\"}");
        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1))).hasMessageContaining("announced none that verified");
        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1))).hasMessageContaining("announced none that verified");
        // The one after the first withheld claim was refused; nothing since.
        verify(http, times(3)).call(eq(SEALING), eq("POST"), any(), any());
    }
}

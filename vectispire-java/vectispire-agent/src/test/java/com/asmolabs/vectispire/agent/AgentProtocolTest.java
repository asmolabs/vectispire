package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

@DisplayName("the four calls an agent knows")
class AgentProtocolTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PRIVATE_KEY = "test-agent-mock-private-key-material";

    private final SealedEnvelope envelopes = new SealedEnvelope();
    private final SealedEnvelope.KeyPair keyPair = envelopes.generateKeyPair();

    private AgentHttp http;
    private AgentProtocol protocol;

    @BeforeEach
    void wire() {
        http = mock(AgentHttp.class);
        protocol = new AgentProtocol(http, JSON, keyPair);
    }

    @Test
    @DisplayName("a contract disagreement is its own error, because its fix is a deployment")
    void aContractMismatchIsDistinct() {
        answers(409, "{\"detail\":\"Update the agent.\"}");

        assertThatThrownBy(() -> protocol.hello(description()))
                .isInstanceOf(AgentProtocol.ContractMismatchException.class)
                .hasMessageContaining("Update the agent.");
    }

    @Test
    @DisplayName("an agent built without a version announces none, instead of failing to start or saying \"1\"")
    @SuppressWarnings("unchecked")
    void aMissingVersionIsLeftOut() {
        // The version came from configuration, defaulting to "1" for every agent; it now comes
        // from build-info, which a build may lack — and `Map.of` throws on a null value, which
        // would have stopped the agent at its first call. A 409 is answered so the call is made
        // and its body inspected, whatever the control plane would have said.
        answers(409, "{\"detail\":\"Update the agent.\"}");

        assertThatThrownBy(() -> protocol.hello(new AgentProtocol.Description("host", "linux", null, "docker")))
                .isInstanceOf(AgentProtocol.ContractMismatchException.class);
        assertThatThrownBy(() -> protocol.hello(new AgentProtocol.Description("host", "linux", "2.3.4", "docker")))
                .isInstanceOf(AgentProtocol.ContractMismatchException.class);

        ArgumentCaptor<Object> bodies = ArgumentCaptor.forClass(Object.class);
        verify(http, times(2)).call(eq("/api/v1/agent/hello"), eq("POST"), bodies.capture(), any());
        assertThat((java.util.Map<String, Object>) bodies.getAllValues().get(0)).doesNotContainKey("version");
        assertThat((java.util.Map<String, Object>) bodies.getAllValues().get(1)).containsEntry("version", "2.3.4");
    }

    @Test
    void aRefusedKeyIsItsOwnErrorToo() {
        answers(401, "{\"detail\":\"API key refused.\"}");

        assertThatThrownBy(() -> protocol.hello(description()))
                .isInstanceOf(AgentProtocol.UnauthorizedException.class);
    }

    @Test
    @DisplayName("204 means no work, and is read from the status alone")
    void anEmptyQueueIsAStatusCode() {
        answers(204, "");

        assertThat(protocol.claim(Duration.ofSeconds(1))).isEmpty();
    }

    @Test
    @DisplayName("a sealed deployment key is opened before the task is handed on")
    void sealedKeysAreOpened() throws Exception {
        String sealed = envelopes.seal(keyPair.publicKey(), PRIVATE_KEY);
        answers(200, JSON.writeValueAsString(assignedWith(sealed)));

        ScanTask task = protocol.claim(Duration.ofSeconds(1)).orElseThrow().task();

        assertThat(((ScanTask.Target.Repository) task.target()).privateKey()).isEqualTo(PRIVATE_KEY);
    }

    @Test
    @DisplayName("an envelope that will not open fails the claim rather than travelling on")
    void anUnopenableEnvelopeFailsLoudly() throws Exception {
        // Sealed for somebody else. Handing the string on would write it to a file and give it to
        // git, and the failure would look like a repository or a permission problem.
        String sealed = envelopes.seal(envelopes.generateKeyPair().publicKey(), PRIVATE_KEY);
        answers(200, JSON.writeValueAsString(assignedWith(sealed)));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not addressed to this process");
    }

    @Test
    @DisplayName("a clear key is refused by an agent that announced a sealing key")
    void aClearKeyAfterAnnouncingSealingIsRefused() throws Exception {
        // This case pinned the downgrade as a feature: a TLS-terminating proxy that strips
        // `sealing_public_key` from the hello gets the key sent in the clear, and the agent took it.
        answers(200, JSON.writeValueAsString(assignedWith(PRIVATE_KEY)));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("announcement was removed");
    }

    @Test
    @DisplayName("a clear key passes through for an agent that announced no sealing key")
    void aClearKeyIsNotTouchedWithoutSealing() throws Exception {
        AgentProtocol unsealed = new AgentProtocol(http, JSON, null);
        answers(200, JSON.writeValueAsString(assignedWith(PRIVATE_KEY)));

        ScanTask task = unsealed.claim(Duration.ofSeconds(1)).orElseThrow().task();

        assertThat(((ScanTask.Target.Repository) task.target()).privateKey()).isEqualTo(PRIVATE_KEY);
    }

    @Test
    @DisplayName("412 names the cause instead of failing the clone later")
    void anUnencryptedLinkIsRefusedByName() {
        answers(412, "{\"detail\":\"Encrypted link required.\"}");

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .hasMessageContaining("Encrypted link required.");
    }

    @Test
    @DisplayName("a rule set is fetched once and cached, because a hash names a content")
    void ruleSetsAreCachedByHash() {
        answers(200, "{\"contentHash\":\"abc\",\"files\":[{\"path\":\"rule-0001.yaml\",\"originalName\":\"o.yaml\",\"content\":\"rules: []\"}]}");

        assertThat(protocol.ruleSet("abc")).hasSize(1);
        assertThat(protocol.ruleSet("abc")).hasSize(1);

        verify(http, times(1)).call(contains("/rules/abc"), anyString(), any(), any());
    }

    @Test
    @DisplayName("409 on a heartbeat means the lease is gone, not that the call failed")
    void aTakenOverLeaseIsFalseNotAnError() {
        answers(409, "{\"detail\":\"Taken over.\"}");

        assertThat(protocol.heartbeat(7L)).isFalse();
    }

    @Test
    void aRefusedRuleSetDoesNotFallBackToTheBundledRules() {
        answers(404, "{\"detail\":\"No rule set with hash abc.\"}");

        // Scanning with fewer rules would hand back a shorter list, which reads as "analyzed,
        // those issues are gone".
        assertThatThrownBy(() -> protocol.ruleSet("abc")).isInstanceOf(IllegalStateException.class);
    }

    private void answers(int status, String body) {
        when(http.call(anyString(), anyString(), any(), any()))
                .thenReturn(new AgentHttp.Response(status, parse(body)));
    }

    private static JsonNode parse(String body) {
        try {
            return body == null || body.isEmpty() ? JSON.nullNode() : JSON.readTree(body);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static AgentProtocol.AssignedTask assignedWithToken(String token) {
        return new AgentProtocol.AssignedTask(
                7L,
                new ScanTask(
                        new ScanTask.Target.Repository("https://gitlab.example.com/t/s.git", "main", "", null,
                                new ScanTask.Target.HttpsCredential("gitlab.example.com", null, token)),
                        null,
                        java.util.Set.of()));
    }

    @Test
    @DisplayName("a sealed HTTPS token is opened before the task is handed on")
    void aSealedTokenIsOpened() throws Exception {
        answers(200, JSON.writeValueAsString(assignedWithToken(envelopes.seal(keyPair.publicKey(), "glpat-secret"))));

        ScanTask task = protocol.claim(Duration.ofSeconds(1)).orElseThrow().task();

        assertThat(((ScanTask.Target.Repository) task.target()).https().token()).isEqualTo("glpat-secret");
    }

    @Test
    @DisplayName("a token that arrives in the clear after sealing was announced is refused")
    void aClearTokenAfterAnnouncingSealingIsRefused() throws Exception {
        answers(200, JSON.writeValueAsString(assignedWithToken("glpat-secret")));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HTTPS token arrived unsealed");
    }

    private static AgentProtocol.AssignedTask assignedWith(String privateKey) {
        return new AgentProtocol.AssignedTask(
                7L,
                new ScanTask(
                        new ScanTask.Target.Repository("git@example.invalid:t/s.git", "main", "", privateKey),
                        null,
                        java.util.Set.of(ScanTask.Step.DEPENDENCIES)));
    }

    private static AgentProtocol.Description description() {
        return new AgentProtocol.Description("host", "linux", "1", "docker");
    }
}

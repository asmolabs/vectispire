package com.asmolabs.zanshin.agent;

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

import com.asmolabs.zanshin.common.domain.crypto.SealedEnvelope;
import com.asmolabs.zanshin.common.scanning.ScanTask;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the four calls an agent knows")
class AgentProtocolTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----";

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
    @DisplayName("a clear key passes through untouched")
    void aClearKeyIsNotTouched() throws Exception {
        answers(200, JSON.writeValueAsString(assignedWith(PRIVATE_KEY)));

        ScanTask task = protocol.claim(Duration.ofSeconds(1)).orElseThrow().task();

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

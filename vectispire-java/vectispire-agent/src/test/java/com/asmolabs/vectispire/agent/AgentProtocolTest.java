package com.asmolabs.vectispire.agent;

import static com.asmolabs.vectispire.common.domain.scans.FailureKind.PERMANENT;
import static com.asmolabs.vectispire.common.domain.scans.FailureKind.TRANSIENT;
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

        assertThat(protocol.claim(Duration.ofSeconds(1)).task()).isEmpty();
    }

    @Test
    @DisplayName("the limit is read off every answer to a claim, the empty one included, and absent stays absent")
    void theLimitTravelsOnTheClaim() {
        // The 204 is what an agent at its limit receives. Without the header there, a raised
        // limit would reach it only at its next restart.
        when(http.call(anyString(), anyString(), any(), any())).thenReturn(new AgentHttp.Response(
                204, JSON.nullNode(), java.net.http.HttpHeaders.of(
                        java.util.Map.of("x-vectispire-max-concurrent", java.util.List.of("4")), (name, value) -> true)));
        assertThat(protocol.claim(Duration.ofSeconds(1)).maxConcurrent()).hasValue(4);

        // An older control plane sends none: the agent keeps what its hello said.
        answers(204, "");
        assertThat(protocol.claim(Duration.ofSeconds(1)).maxConcurrent()).isEmpty();
    }

    @Test
    @DisplayName("a sealed deployment key is opened before the task is handed on")
    void sealedKeysAreOpened() throws Exception {
        String sealed = envelopes.seal(keyPair.publicKey(), PRIVATE_KEY, SealedEnvelope.Context.deploymentKey());
        answers(200, JSON.writeValueAsString(assignedWith(sealed)));

        ScanTask task = protocol.claim(Duration.ofSeconds(1)).task().orElseThrow().task();

        assertThat(((ScanTask.Target.Repository) task.target()).privateKey()).isEqualTo(PRIVATE_KEY);
    }

    @Test
    @DisplayName("an envelope that will not open fails the claim rather than travelling on")
    void anUnopenableEnvelopeFailsLoudly() throws Exception {
        // Sealed for somebody else. Handing the string on would write it to a file and give it to
        // git, and the failure would look like a repository or a permission problem.
        String sealed = envelopes.seal(envelopes.generateKeyPair().publicKey(), PRIVATE_KEY, SealedEnvelope.Context.deploymentKey());
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

        ScanTask task = unsealed.claim(Duration.ofSeconds(1)).task().orElseThrow().task();

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

    /** A manifest as the control plane serves it, and the reference naming it. */
    private static com.asmolabs.vectispire.common.domain.plugins.PluginManifest manifest() {
        return new com.asmolabs.vectispire.common.domain.plugins.PluginManifest("acme-lint", "ACME",
                "registry.acme.internal/acme-lint@sha256:" + "a".repeat(64),
                java.util.Set.of(com.asmolabs.vectispire.common.domain.plugins.Language.JAVA),
                java.util.List.of("{source}"), null, null, false, null, null);
    }

    @Test
    @DisplayName("a plugin's manifest is fetched by id and digest, and cached once it hashes to that digest")
    void pluginsAreFetchedByReferenceAndCached() throws Exception {
        var manifest = manifest();
        var reference = new com.asmolabs.vectispire.common.domain.plugins.PluginRef(manifest.id(), manifest.digest());
        answers(200, JSON.writeValueAsString(manifest));

        assertThat(protocol.plugin(reference)).isEqualTo(manifest);
        assertThat(protocol.plugin(reference)).isEqualTo(manifest);

        verify(http, times(1)).call(contains("/api/v1/agent/plugins/acme-lint/" + manifest.digest()), anyString(), any(), any());
    }

    @Test
    @DisplayName("an answer that does not hash to the digest is not cached: the runner refuses it, and asks again next time")
    void aWrongAnswerIsNotKept() throws Exception {
        var manifest = manifest();
        var reference = new com.asmolabs.vectispire.common.domain.plugins.PluginRef(manifest.id(), "b".repeat(64));
        answers(200, JSON.writeValueAsString(manifest));

        protocol.plugin(reference);
        protocol.plugin(reference);

        verify(http, times(2)).call(contains("/api/v1/agent/plugins/"), anyString(), any(), any());
    }

    @Test
    @DisplayName("a plugin the control plane does not know is an error, never something else run in its place")
    void anUnknownPluginIsRefused() {
        answers(404, "{\"detail\":\"No plugin.\"}");

        assertThatThrownBy(() -> protocol.plugin(new com.asmolabs.vectispire.common.domain.plugins.PluginRef("x1", "c".repeat(64))))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("409 on a heartbeat means the lease is gone, not that the call failed")
    void aTakenOverLeaseIsFalseNotAnError() {
        answers(409, "{\"detail\":\"Taken over.\"}");

        assertThat(protocol.heartbeat(7L)).isFalse();
    }

    @Test
    @DisplayName("a claim reads the attempt it is, and a task that cannot be opened is still named for its report")
    void theClaimCarriesItsAttempt() throws Exception {
        answers(200, "{\"scanId\":7,\"attempt\":2,\"task\":" + JSON.writeValueAsString(assignedWith(null).task()) + "}");
        assertThat(protocol.claim(Duration.ofSeconds(1)).task().orElseThrow().attempt()).isEqualTo(2);

        String sealed = envelopes.seal(envelopes.generateKeyPair().publicKey(), PRIVATE_KEY, SealedEnvelope.Context.deploymentKey());
        answers(200, "{\"scanId\":8,\"attempt\":1,\"task\":" + JSON.writeValueAsString(assignedWith(sealed).task()) + "}");
        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOfSatisfying(AgentProtocol.UnusableTaskException.class, unusable -> {
                    assertThat(unusable.assigned().scanId()).isEqualTo(8L);
                    assertThat(unusable.assigned().attempt()).isEqualTo(1);
                });
    }

    @Test
    @DisplayName("a failure report names the attempt, and its answer says what became of the scan")
    void aFailureReportIsSent() throws Exception {
        AgentProtocol.AssignedTask assigned = new AgentProtocol.AssignedTask(7L, 2, assignedWith(null).task());
        reportAnswers(200, "{\"retried\":true,\"attempt\":2,\"maxAttempts\":3}");

        assertThat(protocol.reportFailure(assigned, "clone refused", TRANSIENT)).isEqualTo(AgentProtocol.FailureReported.RETRIED);
        ArgumentCaptor<Object> body = ArgumentCaptor.forClass(Object.class);
        verify(http).call(eq("/api/v1/agent/jobs/7/failure"), eq("POST"), body.capture(), any(), any());
        JsonNode sent = JSON.readTree(((AgentHttp.RawJson) body.getValue()).text());
        assertThat(sent.path("attempt").asInt()).isEqualTo(2);
        assertThat(sent.path("reason").asText()).isEqualTo("clone refused");
        assertThat(sent.path("kind").asText()).isEqualTo("transient");

        reportAnswers(200, "{\"retried\":false,\"attempt\":3,\"maxAttempts\":3}");
        assertThat(protocol.reportFailure(assigned, "clone refused", TRANSIENT)).isEqualTo(AgentProtocol.FailureReported.FAILED);
        reportAnswers(409, "{\"detail\":\"Not yours.\"}");
        assertThat(protocol.reportFailure(assigned, "clone refused", TRANSIENT)).isEqualTo(AgentProtocol.FailureReported.NOT_YOURS);
        reportAnswers(403, "{\"detail\":\"Unsigned.\"}");
        assertThatThrownBy(() -> protocol.reportFailure(assigned, "clone refused", TRANSIENT))
                .isInstanceOf(AgentProtocol.UnauthorizedException.class);
    }

    /** The compatibility half: an older control plane has no such route, and says so with a 404. */
    @Test
    @DisplayName("an older control plane — a 404, or a claim with no attempt — is 'not supported', not an error")
    void anOlderControlPlaneTakesNoReport() {
        reportAnswers(404, "{\"detail\":\"Not Found\"}");
        assertThat(protocol.reportFailure(new AgentProtocol.AssignedTask(7L, 1, assignedWith(null).task()), "x", TRANSIENT))
                .isEqualTo(AgentProtocol.FailureReported.NOT_SUPPORTED);

        assertThat(protocol.reportFailure(assignedWith(null), "x", TRANSIENT)).isEqualTo(AgentProtocol.FailureReported.NOT_SUPPORTED);
        verify(http, times(1)).call(anyString(), anyString(), any(), any(), any());
    }

    @Test
    @DisplayName("a report is signed with the pinned key, over the bytes sent, as a failure and not as a result")
    void aFailureReportIsSigned() throws Exception {
        var signing = com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.generate();
        AgentProtocol signed = new AgentProtocol(http, JSON, keyPair, signing.privateKey());
        reportAnswers(200, "{\"retried\":true}");

        signed.reportFailure(new AgentProtocol.AssignedTask(7L, 1, assignedWith(null).task()), "clone refused", PERMANENT);

        ArgumentCaptor<Object> body = ArgumentCaptor.forClass(Object.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<java.util.Map<String, String>> headers = ArgumentCaptor.forClass(java.util.Map.class);
        verify(http).call(eq("/api/v1/agent/jobs/7/failure"), eq("POST"), body.capture(), any(), headers.capture());
        byte[] sent = ((AgentHttp.RawJson) body.getValue()).text().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String signature = headers.getValue().get(com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.HEADER);
        assertThat(com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.verifyFailure(
                        signing.publicKey(), 7L, sent, signature))
                .isTrue();
        assertThat(com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.verify(signing.publicKey(), 7L, sent, signature))
                .isFalse();
    }

    @Test
    @DisplayName("a permanent failure is reported as such, and the unusable task says it is one")
    void aPermanentFailureIsSentAsSuch() throws Exception {
        reportAnswers(200, "{\"retried\":false,\"permanent\":true,\"attempt\":1,\"maxAttempts\":3}");

        assertThat(protocol.reportFailure(new AgentProtocol.AssignedTask(7L, 1, assignedWith(null).task()),
                        "host key changed", PERMANENT))
                .isEqualTo(AgentProtocol.FailureReported.FAILED);
        ArgumentCaptor<Object> body = ArgumentCaptor.forClass(Object.class);
        verify(http).call(eq("/api/v1/agent/jobs/7/failure"), eq("POST"), body.capture(), any(), any());
        assertThat(JSON.readTree(((AgentHttp.RawJson) body.getValue()).text()).path("kind").asText()).isEqualTo("permanent");

        assertThat(new AgentProtocol.UnusableTaskException(assignedWith(null), "sealed for somebody else").failureKind())
                .isEqualTo(PERMANENT);
    }

    private void reportAnswers(int status, String body) {
        when(http.call(anyString(), anyString(), any(), any(), any()))
                .thenReturn(new AgentHttp.Response(status, parse(body)));
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
        answers(200, JSON.writeValueAsString(assignedWithToken(envelopes.seal(keyPair.publicKey(), "glpat-secret", SealedEnvelope.Context.httpsToken("gitlab.example.com", null)))));

        ScanTask task = protocol.claim(Duration.ofSeconds(1)).task().orElseThrow().task();

        assertThat(((ScanTask.Target.Repository) task.target()).https().token()).isEqualTo("glpat-secret");
    }

    /**
     * The audit of 10 October 2026: a TLS-terminating proxy rewrote the host the token travels
     * with, left the envelope alone, and the agent opened it and cloned from the proxy's server
     * with the forge's token.
     */
    @Test
    @DisplayName("a token whose host was rewritten on the way is refused, never opened for the new host")
    void aTokenWhoseHostWasRewrittenIsRefused() throws Exception {
        String sealed = envelopes.seal(keyPair.publicKey(), "glpat-secret",
                SealedEnvelope.Context.httpsToken("gitlab.example.com", null));
        answers(200, JSON.writeValueAsString(new AgentProtocol.AssignedTask(
                7L,
                new ScanTask(
                        new ScanTask.Target.Repository("https://attacker.example/t/s.git", "main", "", null,
                                new ScanTask.Target.HttpsCredential("attacker.example", null, sealed)),
                        null,
                        java.util.Set.of()))));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HTTPS token could not be opened");
    }

    @Test
    @DisplayName("a deployment key's envelope moved into the token's field is refused, not sent as a password")
    void aDeploymentKeyMovedIntoTheTokenIsRefused() throws Exception {
        answers(200, JSON.writeValueAsString(assignedWithToken(
                envelopes.seal(keyPair.publicKey(), PRIVATE_KEY, SealedEnvelope.Context.deploymentKey()))));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HTTPS token could not be opened");
    }

    @Test
    @DisplayName("a credential sealed by an older control plane is refused with that cause")
    void aPreviousFormatIsRefusedWithItsCause() throws Exception {
        answers(200, JSON.writeValueAsString(assignedWithToken("sealed:v1:QUJDREVGRw==")));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("older than this agent");
    }

    @Test
    @DisplayName("a token that arrives in the clear after sealing was announced is refused")
    void aClearTokenAfterAnnouncingSealingIsRefused() throws Exception {
        answers(200, JSON.writeValueAsString(assignedWithToken("glpat-secret")));

        assertThatThrownBy(() -> protocol.claim(Duration.ofSeconds(1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HTTPS token arrived unsealed");
    }

    /**
     * A task with every field set to something other than its default, as the control plane builds
     * it before sealing: the key and the token given here are the clear ones.
     */
    private static ScanTask everyField(String privateKey, ScanTask.Target.HttpsCredential https) {
        return new ScanTask(
                new ScanTask.Target.Repository("https://gitlab.example.com/t/s.git", "release", "services/api", privateKey, https),
                "f".repeat(64),
                java.util.Set.of(ScanTask.Step.DEPENDENCIES, ScanTask.Step.SAST),
                java.util.List.of(
                        new com.asmolabs.vectispire.common.domain.plugins.PluginRef("acme-lint", "a".repeat(64)),
                        new com.asmolabs.vectispire.common.domain.plugins.PluginRef("acme-sarif", "b".repeat(64))));
    }

    @Test
    @DisplayName("opening the credentials keeps every other field of the task, its plugins included")
    void unsealingKeepsTheWholeTask() throws Exception {
        // The rebuild that opened the envelopes named the fields it copied, and the plugins were not
        // among them: every credentialed repository a remote agent scanned ran no plugin, and each
        // plugin read as absent — a failure — on a scan that never tried it.
        var token = new ScanTask.Target.HttpsCredential("gitlab.example.com", "ci", "glpat-secret");
        ScanTask clear = everyField(PRIVATE_KEY, token);
        ScanTask sealed = everyField(
                envelopes.seal(keyPair.publicKey(), PRIVATE_KEY, SealedEnvelope.Context.deploymentKey()),
                new ScanTask.Target.HttpsCredential(token.host(), token.username(), envelopes.seal(keyPair.publicKey(), token.token(), SealedEnvelope.Context.httpsToken(token.host(), token.username()))));
        answers(200, JSON.writeValueAsString(new AgentProtocol.AssignedTask(7L, sealed)));

        // The whole record, not the plugins alone: a field added to the task later is dropped by a
        // rebuild in exactly this way.
        assertThat(protocol.claim(Duration.ofSeconds(1)).task().orElseThrow())
                .isEqualTo(new AgentProtocol.AssignedTask(7L, clear));
    }

    @Test
    @DisplayName("a task with only one sealed credential keeps its plugins too")
    void unsealingOneCredentialKeepsThePlugins() throws Exception {
        ScanTask keyOnly = everyField(envelopes.seal(keyPair.publicKey(), PRIVATE_KEY, SealedEnvelope.Context.deploymentKey()), null);
        answers(200, JSON.writeValueAsString(new AgentProtocol.AssignedTask(7L, keyOnly)));
        assertThat(protocol.claim(Duration.ofSeconds(1)).task().orElseThrow().task())
                .isEqualTo(everyField(PRIVATE_KEY, null));

        var token = new ScanTask.Target.HttpsCredential("gitlab.example.com", null, "glpat-secret");
        ScanTask tokenOnly = everyField(null, new ScanTask.Target.HttpsCredential(
                token.host(), token.username(), envelopes.seal(keyPair.publicKey(), token.token(), SealedEnvelope.Context.httpsToken(token.host(), token.username()))));
        answers(200, JSON.writeValueAsString(new AgentProtocol.AssignedTask(7L, tokenOnly)));
        assertThat(protocol.claim(Duration.ofSeconds(1)).task().orElseThrow().task())
                .isEqualTo(everyField(null, token));
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

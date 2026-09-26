package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SealingKeyAttestation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * An agent's sealing key, and the credentials sealed for it, through the real routes (decision 0031).
 *
 * <p>The proxy this protects against sits between the agent and the control plane, so every test
 * here plays the proxy's part with the one thing a proxy can do: change what the agent sent. It
 * removes the key, puts its own in, replays an older announcement. The control plane must seal for
 * the key the agent's pinned signing key vouched for, and for nothing else — and never fall back on
 * the clear.
 */
@DisplayName("an agent's sealing key, and what is sealed for it")
class AgentSealingKeyRoutesTest extends ApiTestBase {

    private static final String DEPLOY_KEY = "-----BEGIN DUMMY PRIVATE KEY-----\nzq7-deploy-secret\n-----END DUMMY PRIVATE KEY-----";

    @Autowired
    private AgentRepository agents;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AuditLogRepository auditEntries;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private SettingsService settings;

    private final SealedEnvelope envelopes = new SealedEnvelope();

    /** @param signingKey the private half of the pinned key, null when none is pinned */
    private record Enrolled(UUID id, String token, String signingKey) {}

    private Enrolled delegatedAgent(boolean pinned) throws Exception {
        JsonNode declared = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"edge-" + System.nanoTime() + "\", \"credentials_mode\": \"delegated\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        UUID id = UUID.fromString(declared.get("id").asText());
        String token = declared.get("secret").asText();
        return new Enrolled(id, token, pinned ? pin(id) : null);
    }

    private String pin(UUID id) throws Exception {
        String body = mvc.perform(authenticated(put("/api/v1/admin/agents/" + id + "/signing-key"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"generate\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).path("privateKey").asText();
    }

    private ResultActions announce(Enrolled agent, String sealingKey, long generation, String signature) throws Exception {
        return mvc.perform(post("/api/v1/agent/sealing-key")
                .header("Authorization", "Bearer " + agent.token())
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of("public_key", sealingKey, "generation", generation, "signature", signature))));
    }

    /** What an agent built from this version sends after its hello. */
    private ResultActions announceSigned(Enrolled agent, SealedEnvelope.KeyPair pair, long generation) throws Exception {
        return announce(agent, pair.publicKey(), generation,
                SealingKeyAttestation.sign(agent.signingKey(), agent.id(), generation, pair.publicKey()));
    }

    private ResultActions hello(Enrolled agent, String sealingKey) throws Exception {
        String body = sealingKey == null
                ? "{\"contract_version\": \"" + AgentContract.VERSION + "\"}"
                : "{\"contract_version\": \"" + AgentContract.VERSION + "\", \"sealing_public_key\": \"" + sealingKey + "\"}";
        return mvc.perform(post("/api/v1/agent/hello")
                .header("Authorization", "Bearer " + agent.token())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    /**
     * One poll that does not wait. A task, or nothing, comes back through the {@code DeferredResult}
     * and needs the async dispatch; a refusal raised by the immediate claim is answered at once.
     */
    private ResultActions poll(Enrolled agent) throws Exception {
        ResultActions first = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent.token()));
        MvcResult started = first.andReturn();
        return started.getRequest().isAsyncStarted() ? mvc.perform(asyncDispatch(started)) : first;
    }

    private AgentEntity row(Enrolled agent) {
        return agents.findById(agent.id()).orElseThrow();
    }

    private long audited(AuditOperation operation) {
        return auditEntries.findAll().stream()
                .filter(entry -> operation.wireName().equals(entry.getOperationType()))
                .count();
    }

    @Test
    @DisplayName("a key signed with the pinned key is accepted, recorded with its generation, and audited")
    void aSignedKeyIsAccepted() throws Exception {
        Enrolled agent = delegatedAgent(true);
        SealedEnvelope.KeyPair pair = envelopes.generateKeyPair();

        announceSigned(agent, pair, 1_000L).andExpect(status().isNoContent());

        assertThat(row(agent).getSealingPublicKey()).isEqualTo(pair.publicKey());
        assertThat(row(agent).getSealingKeyGeneration()).isEqualTo(1_000L);
        assertThat(audited(AuditOperation.AGENT_SEALING_KEY_ACCEPTED)).isEqualTo(1);
        mvc.perform(authenticated(get("/api/v1/admin/agents"), asAdmin()))
                .andExpect(jsonPath("$[0].sealsCredentials").value(true));

        // Repeated as it stands — a retry, a second call after a timeout: accepted, and not a rotation.
        announceSigned(agent, pair, 1_000L).andExpect(status().isNoContent());
        assertThat(audited(AuditOperation.AGENT_SEALING_KEY_ACCEPTED)).isEqualTo(1);
    }

    /**
     * The unpinned policy. There is nothing to verify a signature against, and no first-use trust to
     * fall back on: the pair is remade at every start, so a key trusted on first sight would have to
     * be trusted again, unsigned, at the next.
     */
    @Test
    @DisplayName("an agent with no pinned signing key has no sealing key accepted, signed or not")
    void unpinnedIsRefused() throws Exception {
        Enrolled agent = delegatedAgent(false);
        SealedEnvelope.KeyPair pair = envelopes.generateKeyPair();
        String selfSigned = SealingKeyAttestation.sign(ResultAttestation.generate().privateKey(), agent.id(), 1_000L, pair.publicKey());

        announce(agent, pair.publicKey(), 1_000L, selfSigned)
                .andExpect(status().isPreconditionFailed())
                .andExpect(status().reason(org.hamcrest.Matchers.containsString("No signing key is pinned")));

        assertThat(row(agent).getSealingPublicKey()).isNull();
    }

    @Test
    @DisplayName("a substituted key under a signature that does not verify is refused, audited, and signalled")
    void aSubstitutedKeyIsRefused() throws Exception {
        exportSiemEvents();
        Enrolled agent = delegatedAgent(true);
        SealedEnvelope.KeyPair genuine = envelopes.generateKeyPair();
        SealedEnvelope.KeyPair substitute = envelopes.generateKeyPair();
        String genuineSignature = SealingKeyAttestation.sign(agent.signingKey(), agent.id(), 1_000L, genuine.publicKey());
        String otherSigner = SealingKeyAttestation.sign(
                ResultAttestation.generate().privateKey(), agent.id(), 1_000L, substitute.publicKey());

        // The agent's own signature, moved onto another key; then a key signed by somebody else.
        announce(agent, substitute.publicKey(), 1_000L, genuineSignature).andExpect(status().isForbidden());
        announce(agent, substitute.publicKey(), 1_000L, otherSigner).andExpect(status().isForbidden());
        announce(agent, substitute.publicKey(), 1_000L, "").andExpect(status().isForbidden());

        assertThat(row(agent).getSealingPublicKey()).isNull();
        assertThat(audited(AuditOperation.AGENT_SEALING_KEY_REFUSED)).isEqualTo(3);
        assertThat(queuedSiemTypes()).contains("AGENT_SEALING_KEY_REFUSED");
    }

    @Test
    @DisplayName("an announcement signed for another agent sharing the same signing key is refused")
    void anotherAgentsAnnouncementIsRefused() throws Exception {
        Enrolled first = delegatedAgent(true);
        Enrolled second = delegatedAgent(false);
        // An operator who put one signing key on two agents.
        String pinnedPublic = row(first).getSigningPublicKey();
        mvc.perform(authenticated(put("/api/v1/admin/agents/" + second.id() + "/signing-key"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("public_key", pinnedPublic))))
                .andExpect(status().isOk());

        SealedEnvelope.KeyPair firstsPair = envelopes.generateKeyPair();
        String forFirst = SealingKeyAttestation.sign(first.signingKey(), first.id(), 1_000L, firstsPair.publicKey());

        announce(second, firstsPair.publicKey(), 1_000L, forFirst).andExpect(status().isForbidden());
        assertThat(row(second).getSealingPublicKey()).isNull();
    }

    @Test
    @DisplayName("a newer signed key replaces the old one; an older one is refused and audited")
    void rotationOnlyForwards() throws Exception {
        Enrolled agent = delegatedAgent(true);
        SealedEnvelope.KeyPair before = envelopes.generateKeyPair();
        SealedEnvelope.KeyPair restarted = envelopes.generateKeyPair();

        announceSigned(agent, before, 1_000L).andExpect(status().isNoContent());
        announceSigned(agent, restarted, 2_000L).andExpect(status().isNoContent());
        assertThat(row(agent).getSealingPublicKey()).isEqualTo(restarted.publicKey());
        assertThat(audited(AuditOperation.AGENT_SEALING_KEY_ACCEPTED)).isEqualTo(2);

        // The first announcement, recorded on the way and sent again: validly signed, and stale.
        announceSigned(agent, before, 1_000L).andExpect(status().isConflict());
        // A different key under the generation already held is no better.
        announceSigned(agent, envelopes.generateKeyPair(), 2_000L).andExpect(status().isConflict());

        assertThat(row(agent).getSealingPublicKey()).isEqualTo(restarted.publicKey());
        assertThat(row(agent).getSealingKeyGeneration()).isEqualTo(2_000L);
        assertThat(audited(AuditOperation.AGENT_SEALING_KEY_REFUSED)).isEqualTo(2);
    }

    @Test
    @DisplayName("a hello with no key, or an unsigned one, leaves the accepted key where it is")
    void helloNeverTouchesTheKey() throws Exception {
        Enrolled agent = delegatedAgent(true);
        SealedEnvelope.KeyPair pair = envelopes.generateKeyPair();
        announceSigned(agent, pair, 1_000L).andExpect(status().isNoContent());

        hello(agent, null).andExpect(status().isOk());
        assertThat(row(agent).getSealingPublicKey()).isEqualTo(pair.publicKey());

        hello(agent, envelopes.generateKeyPair().publicKey()).andExpect(status().isOk());
        assertThat(row(agent).getSealingPublicKey()).isEqualTo(pair.publicKey());
        assertThat(row(agent).getSealingKeyGeneration()).isEqualTo(1_000L);
    }

    /**
     * The first half of the upgrade matrix: an agent built before this version says hello with an
     * unsigned key, and nothing else. Its hello works and its image scans run; no key it announced is
     * believed, so a delegated credential is withheld with a message it logs.
     */
    @Test
    @DisplayName("an older agent's unsigned key is not recorded: its hello answers, its credentials are withheld")
    void anOlderAgentIsNotBelieved() throws Exception {
        Enrolled agent = delegatedAgent(true);

        hello(agent, envelopes.generateKeyPair().publicKey()).andExpect(status().isOk());

        assertThat(row(agent).getSealingPublicKey()).isNull();
        mvc.perform(authenticated(get("/api/v1/admin/agents"), asAdmin()))
                .andExpect(jsonPath("$[0].sealsCredentials").value(false));
    }

    @Test
    @DisplayName("an administrator's change saved over a newer key does not put the old one back")
    void savingTheRowCannotRollTheKeyBack() throws Exception {
        Enrolled agent = delegatedAgent(true);
        SealedEnvelope.KeyPair before = envelopes.generateKeyPair();
        announceSigned(agent, before, 1_000L).andExpect(status().isNoContent());

        // Read by an administrator's change, then the agent restarts and announces, then the change
        // is saved — the interleaving a read-then-save goes through.
        AgentEntity readBefore = row(agent);
        SealedEnvelope.KeyPair restarted = envelopes.generateKeyPair();
        announceSigned(agent, restarted, 2_000L).andExpect(status().isNoContent());
        readBefore.setLabels("dmz");
        agents.save(readBefore);

        assertThat(row(agent).getLabels()).isEqualTo("dmz");
        assertThat(row(agent).getSealingPublicKey()).isEqualTo(restarted.publicKey());
        assertThat(row(agent).getSealingKeyGeneration()).isEqualTo(2_000L);
    }

    /**
     * End to end: a deployment key registered through the routes, a delegated agent that proved its
     * key, a claim — and the credential opens with the agent's private half, and nobody else's.
     */
    @Test
    @DisplayName("a delegated credential is sealed for the verified key, and for no key a hello announced")
    void theCredentialIsSealedForTheVerifiedKeyOnly() throws Exception {
        Enrolled agent = delegatedAgent(true);
        SealedEnvelope.KeyPair genuine = envelopes.generateKeyPair();
        SealedEnvelope.KeyPair proxys = envelopes.generateKeyPair();
        hello(agent, genuine.publicKey()).andExpect(status().isOk());
        announceSigned(agent, genuine, 1_000L).andExpect(status().isNoContent());
        // The proxy rewrites a later hello with its own key: read by nothing.
        hello(agent, proxys.publicKey()).andExpect(status().isOk());

        long scanId = pendingScanWithDeployKey();
        JsonNode task = json.readTree(poll(agent).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());

        assertThat(task.at("/scanId").asLong()).isEqualTo(scanId);
        String delivered = task.at("/task/target/privateKey").asText();
        assertThat(SealedEnvelope.isSealed(delivered)).isTrue();
        assertThat(delivered).doesNotContain("zq7-deploy-secret");
        assertThat(envelopes.open(genuine, delivered)).contains(DEPLOY_KEY);
        assertThat(envelopes.open(proxys, delivered)).isEmpty();
        assertThat(auditEntries.findAll())
                .anyMatch(entry -> AuditOperation.AGENT_CREDENTIAL_SENT.wireName().equals(entry.getOperationType())
                        && entry.getDescription().contains("verified sealing key"));
    }

    /**
     * The key removed on the way. The agent is pinned and speaks this version, but its announcement
     * never arrived: no clear delivery, whatever the link, and the scan goes back to the queue.
     */
    @Test
    @DisplayName("with the announcement stripped, the claim answers 412 and the credential never leaves")
    void strippedAnnouncementDeliversNothing() throws Exception {
        Enrolled agent = delegatedAgent(true);
        hello(agent, null).andExpect(status().isOk());
        long scanId = pendingScanWithDeployKey();

        String answer = poll(agent)
                .andExpect(status().isPreconditionFailed())
                .andReturn().getResponse().getContentAsString();

        assertThat(answer).doesNotContain("zq7-deploy-secret").contains("announced none that verified");
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(audited(AuditOperation.AGENT_CREDENTIAL_SENT)).isZero();
    }

    @Test
    @DisplayName("an unpinned delegated agent is handed no credential, and told to have one pinned")
    void unpinnedDeliversNothing() throws Exception {
        Enrolled agent = delegatedAgent(false);
        hello(agent, envelopes.generateKeyPair().publicKey()).andExpect(status().isOk());
        pendingScanWithDeployKey();

        poll(agent)
                .andExpect(status().isPreconditionFailed())
                .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("no signing key is pinned")));
        assertThat(audited(AuditOperation.AGENT_CREDENTIAL_SENT)).isZero();
    }

    private long pendingScanWithDeployKey() throws Exception {
        JsonNode key = json.readTree(mvc.perform(authenticated(post("/api/v1/ssh-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "deploy-" + System.nanoTime(), "private_key", DEPLOY_KEY))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        JsonNode repository = json.readTree(mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "url", "git@example.invalid:team/service-" + System.nanoTime() + ".git",
                                "sshKeyId", key.get("id").asText()))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository.get("id").asLong());
        scan.setBranch("main");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        return scans.save(scan).getId();
    }

    private void exportSiemEvents() throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        outbox.deleteAll();
    }

    private List<String> queuedSiemTypes() {
        return outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload()).get("eventType").asText();
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .toList();
    }
}

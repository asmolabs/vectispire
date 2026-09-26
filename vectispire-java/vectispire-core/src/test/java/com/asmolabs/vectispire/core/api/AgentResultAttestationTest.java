package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The attestation on a scan result.
 *
 * <p>{@code submitResult} took an {@code X-Vectispire-Agent-Signature} header, documented it as a
 * cryptographic attestation and published it in the OpenAPI document — and never read the
 * parameter. No agent produced one either. These tests are what makes the header mean something.
 *
 * <p><b>The verification is asserted through the status code that follows it.</b> A result whose
 * attestation is refused answers 403 and never reaches the dispatcher; one whose attestation
 * verifies reaches it and answers 409, because no lease in these tests belongs to the agent. That
 * 409 is therefore the proof the signature was accepted — and it does not require standing up a
 * queued scan to get it.
 */
@DisplayName("a scan result's attestation")
class AgentResultAttestationTest extends ApiTestBase {

    private static final String ARTIFACTS = "{}";

    @Autowired
    private AuditLogRepository auditEntries;

    /** @param token the agent's API key, shown once at creation like a real one */
    private record Enrolled(String id, String token) {}

    private Enrolled declareAgent() throws Exception {
        String body = mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"scanner-" + System.nanoTime() + "\"}"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var answer = json.readTree(body);
        return new Enrolled(answer.path("id").asText(), answer.path("secret").asText());
    }

    private String pinGeneratedKey(String agentId) throws Exception {
        String body = mvc.perform(authenticated(put("/api/v1/admin/agents/" + agentId + "/signing-key"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"generate\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signsResults").value(true))
                .andReturn()
                .getResponse()
                .getContentAsString();

        String privateKey = json.readTree(body).path("privateKey").asText();
        assertThat(ResultAttestation.isUsablePrivateKey(privateKey)).isTrue();
        return privateKey;
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder submit(
            String token, long scanId, String signature) {

        var request = post("/api/v1/agent/jobs/" + scanId + "/result")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(ARTIFACTS);
        return signature == null ? request : request.header(ResultAttestation.HEADER, signature);
    }

    /**
     * The upgrade path, and the state every existing installation is in.
     *
     * <p>An agent with no pinned key behaves exactly as before — otherwise turning this on would
     * stop every fleet in the field at once.
     */
    @Test
    @DisplayName("an agent with no pinned key is accepted unsigned, as before")
    void noPinnedKeyIsUnchanged() throws Exception {
        Enrolled agent = declareAgent();

        mvc.perform(submit(agent.token(), 1L, null)).andExpect(status().isConflict());
    }

    @Test
    @DisplayName("an agent whose key is pinned is refused when it sends no signature")
    void pinnedKeyRefusesUnsigned() throws Exception {
        Enrolled agent = declareAgent();
        pinGeneratedKey(agent.id());

        mvc.perform(submit(agent.token(), 1L, null)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a signature made with the pinned key is accepted")
    void pinnedKeyAcceptsItsOwnSignature() throws Exception {
        Enrolled agent = declareAgent();
        String privateKey = pinGeneratedKey(agent.id());

        String signature = ResultAttestation.sign(privateKey, 1L, ARTIFACTS.getBytes(StandardCharsets.UTF_8));

        mvc.perform(submit(agent.token(), 1L, signature)).andExpect(status().isConflict());
    }

    /**
     * The threat this control exists for, expressed as a test.
     *
     * <p>Whoever steals the API key can still claim tasks. What they cannot do is hand back the
     * empty result that would resolve the target's backlog, because they do not hold the key an
     * operator pinned out of band.
     */
    @Test
    @DisplayName("a stolen API key cannot declare a target clean: another key's signature is refused")
    void aStolenKeyCannotSign() throws Exception {
        Enrolled agent = declareAgent();
        pinGeneratedKey(agent.id());

        ResultAttestation.KeyPair attackers = ResultAttestation.generate();
        String signature =
                ResultAttestation.sign(attackers.privateKey(), 1L, ARTIFACTS.getBytes(StandardCharsets.UTF_8));

        mvc.perform(submit(agent.token(), 1L, signature)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a signature made for another scan is refused — no replaying an empty result")
    void noReplayAcrossScans() throws Exception {
        Enrolled agent = declareAgent();
        String privateKey = pinGeneratedKey(agent.id());

        String forScanOne = ResultAttestation.sign(privateKey, 1L, ARTIFACTS.getBytes(StandardCharsets.UTF_8));

        mvc.perform(submit(agent.token(), 2L, forScanOne)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a refused attestation is written to the audit log, because a silent probe is the point")
    void refusalIsAudited() throws Exception {
        Enrolled agent = declareAgent();
        pinGeneratedKey(agent.id());

        mvc.perform(submit(agent.token(), 1L, null)).andExpect(status().isForbidden());

        assertThat(auditEntries.findAll())
                .anyMatch(entry -> AuditOperation.AGENT_RESULT_REFUSED.wireName().equals(entry.getOperationType()));
    }

    @Test
    @DisplayName("removing the pinned key takes the agent back to its API key alone, and is audited")
    void removingThePinIsAnAct() throws Exception {
        Enrolled agent = declareAgent();
        pinGeneratedKey(agent.id());

        mvc.perform(authenticated(put("/api/v1/admin/agents/" + agent.id() + "/signing-key"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signsResults").value(false));

        mvc.perform(submit(agent.token(), 1L, null)).andExpect(status().isConflict());

        assertThat(auditEntries.findAll())
                .anyMatch(entry -> AuditOperation.AGENT_SIGNING_KEY_PINNED.wireName().equals(entry.getOperationType())
                        && entry.getDescription().contains("removed"));
    }

    @Test
    @DisplayName("a key that is not 32 bytes of base64 is refused when it is pinned, not at the first result")
    void malformedKeyRefusedOnTheWayIn() throws Exception {
        Enrolled agent = declareAgent();

        mvc.perform(authenticated(put("/api/v1/admin/agents/" + agent.id() + "/signing-key"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"c2hvcnQ=\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("pinning a key is an administrator's act, never the agent's own")
    void onlyAnAdministratorPins() throws Exception {
        Enrolled agent = declareAgent();

        mvc.perform(authenticated(put("/api/v1/admin/agents/" + agent.id() + "/signing-key"), asReader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"generate\"}"))
                .andExpect(status().isForbidden());

        // And not over the agent protocol either: the whole point is that the control plane
        // learned this key from somebody who is not the process presenting the token.
        mvc.perform(put("/api/v1/admin/agents/" + agent.id() + "/signing-key")
                        .header("Authorization", "Bearer " + agent.token())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"generate\"}"))
                .andExpect(status().isForbidden());
    }
}

package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What an ordinary account is allowed to <em>do</em>, as opposed to see.
 *
 * <p><b>Written after a route-by-route sweep of the authorization surface, prompted by finding
 * that the blast radius applied no visibility at all.</b> The sweep's worst result was not a read
 * leak: several routes that change or destroy platform-wide state carried nothing but
 * {@code @RequiresAccount}, which every signed-in account satisfies — including {@code ROLE_USER},
 * the role a deployment gives to somebody who is only meant to look at a dashboard.
 *
 * <p>The rule these cases encode is not new; it is the one the rest of the API already follows.
 * Reading is governed by {@code Visibility}, and <b>changing the platform is governed by a role</b>.
 * What was missing is that four routes never said which.
 *
 * <p>Each case names the operation in the terms of its own OpenAPI description, because that is
 * what makes the omission legible: a route documented as "atomically deletes all endpoints and
 * contracts across the entire platform" should not be reachable by a reader.
 */
@DisplayName("what an ordinary account may change")
class AuthorizationSurfaceTest extends ApiTestBase {

    @Test
    @DisplayName("a reader cannot obtain the audit log by asking for the evidence bundle instead")
    void theEvidenceBundleIsNotABackDoorToTheAuditLog() throws Exception {
        // **The same data behind two doors with two different locks.** `/api/v1/audit-log`
        // requires a security lead. The certified evidence bundle — a ZIP built for an external
        // auditor — contains `02_immutable_audit_log.jsonl`, every action by every account since
        // the deployment started, and its route required nothing but a session.
        //
        // The bundle also carries the compliance summary, the triage and risk-acceptance
        // register, and twenty scans' attestations, all built with `Visibility.everything()`
        // hard-coded. It is the most complete leak in the API precisely because its job is to
        // package everything.
        mvc.perform(authenticated(get("/api/v1/compliance/evidence-bundle.zip"), asReader()))
                .andExpect(status().isForbidden());

        mvc.perform(authenticated(get("/api/v1/compliance/evidence-bundle.zip"), asCiso()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("a reader cannot purge the platform's entire API inventory")
    void purgingTheAttackSurfaceIsNotAReadersToDo() throws Exception {
        // "Atomically deletes all endpoints and contracts across the entire platform." One call,
        // no confirmation, no target — and it was reachable by every signed-in account.
        mvc.perform(authenticated(delete("/api/v1/attack-surface"), asReader()))
                .andExpect(status().isForbidden());

        mvc.perform(authenticated(delete("/api/v1/attack-surface"), asAdmin()))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("a reader cannot purge one repository's discovered endpoints either")
    void purgingOneRepositoryIsNotEither() throws Exception {
        mvc.perform(authenticated(delete("/api/v1/repositories/1/apis"), asReader()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a reader cannot ingest VEX statements, which decide what is triaged away")
    void ingestingVexIsAGovernanceAct() throws Exception {
        // A VEX document says "not affected". Accepting one from any account means any account
        // can silence a finding across the estate — the same decision the four-eyes workflow
        // exists to make expensive when a human takes it through the interface.
        mvc.perform(authenticated(post("/api/v1/vex/ingest"), asReader())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("{\"@context\":\"https://openvex.dev/ns\",\"statements\":[]}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a reader cannot trigger an EPSS synchronisation")
    void syncingEpssIsAnOperatorsCall() throws Exception {
        // Outbound, rate-limited by whoever serves it, and repeatable at will by anybody with a
        // session. Not destructive, which is why it is here rather than above, but not a reader's.
        mvc.perform(authenticated(post("/api/v1/epss/sync"), asReader()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a reader cannot make the platform send a notification")
    void sendingATestNotificationIsAnAdministrativeAct() throws Exception {
        // It posts to a configured webhook — somebody else's Slack or Teams. A route that emits
        // outbound traffic on demand belongs to whoever configured the channel.
        mvc.perform(authenticated(post("/api/v1/notifications/test/slack"), asReader()))
                .andExpect(status().isForbidden());
    }
}

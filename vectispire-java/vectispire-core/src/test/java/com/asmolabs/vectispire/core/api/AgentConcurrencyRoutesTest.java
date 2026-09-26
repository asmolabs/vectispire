package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * An agent's {@code max_concurrent}: what the routes accept, and what the claim does with it.
 *
 * <p>Through the real stack on purpose. The bound is a 400 a screen has to show, and the claim is
 * a long-poll route whose 204 has to carry the limit in a header — neither is visible from a
 * service called directly. Concurrency is not tested here: SQLite serializes every write, so two
 * racing polls would prove nothing. {@code ScanQueueIntegrationTest} races them on MySQL and
 * PostgreSQL.
 */
@DisplayName("an agent's concurrency limit, through the routes")
class AgentConcurrencyRoutesTest extends ApiTestBase {

    @Autowired
    private Agents agents;

    @Autowired
    private Scans scans;

    @Autowired
    private Containers containers;

    private record Enrolled(UUID id, String token) {}

    private ResultActions declare(String body) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private Enrolled enrolled(String body) throws Exception {
        JsonNode answer = json.readTree(declare(body).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return new Enrolled(UUID.fromString(answer.get("id").asText()), answer.get("secret").asText());
    }

    private ResultActions change(UUID id, String body) throws Exception {
        return mvc.perform(authenticated(patch("/api/v1/admin/agents/" + id), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    /**
     * One poll that does not wait. The route answers through a {@code DeferredResult}, already set
     * when {@code wait=0}; MockMvc still hands it back as a started async request, and the answer
     * is only written by the dispatch that follows.
     */
    private ResultActions poll(Enrolled agent) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent.token()))
                .andReturn();
        return mvc.perform(asyncDispatch(started));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 17, 200})
    @DisplayName("a declaration outside 1..16 is refused with a 400, and writes nothing")
    void refusesADeclarationOutOfBounds(int requested) throws Exception {
        declare("{\"name\": \"edge\", \"max_concurrent\": " + requested + "}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("between 1 and 16")));

        assertThat(agents.findAllByOrderByNameAsc()).isEmpty();
    }

    @Test
    @DisplayName("a declaration that says nothing runs one scan at a time; the bound itself is accepted")
    void defaultsToOne() throws Exception {
        UUID quiet = enrolled("{\"name\": \"quiet\"}").id();
        UUID wide = enrolled("{\"name\": \"wide\", \"max_concurrent\": 16}").id();

        assertThat(agents.findById(quiet).orElseThrow().getMaxConcurrent()).isEqualTo(1);
        assertThat(agents.findById(wide).orElseThrow().getMaxConcurrent()).isEqualTo(16);
    }

    @Test
    @DisplayName("a change outside the bound is refused and leaves the agent as it was; an absent one changes nothing")
    void boundsAChange() throws Exception {
        UUID id = enrolled("{\"name\": \"edge\", \"max_concurrent\": 3}").id();

        change(id, "{\"max_concurrent\": 0}").andExpect(status().isBadRequest());
        change(id, "{\"max_concurrent\": 17}").andExpect(status().isBadRequest());
        assertThat(agents.findById(id).orElseThrow().getMaxConcurrent()).isEqualTo(3);

        // Null means "left as it was" — the screen's enable toggle sends only `enabled`.
        change(id, "{\"enabled\": false}").andExpect(status().isOk());
        assertThat(agents.findById(id).orElseThrow().getMaxConcurrent()).isEqualTo(3);

        change(id, "{\"max_concurrent\": 5}").andExpect(status().isOk());
        assertThat(agents.findById(id).orElseThrow().getMaxConcurrent()).isEqualTo(5);
    }

    @Test
    @DisplayName("a row from before the bound is shown and announced as the limit the queue applies")
    void anOldRowIsReadClamped() throws Exception {
        Enrolled agent = enrolled("{\"name\": \"legacy\"}");
        var row = agents.findById(agent.id()).orElseThrow();
        row.setMaxConcurrent(50);
        agents.save(row);

        mvc.perform(authenticated(get("/api/v1/admin/agents"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].maxConcurrent").value(16));
        poll(agent).andExpect(status().isNoContent()).andExpect(header().string(AgentConcurrency.HEADER, "16"));
    }

    @Test
    @DisplayName("the claim stops at the limit, follows a changed limit, and does not count a lapsed lease")
    void theClaimHonoursTheLimit() throws Exception {
        Enrolled agent = enrolled("{\"name\": \"edge\", \"max_concurrent\": 1}");
        long first = pending();
        long second = pending();

        poll(agent).andExpect(status().isOk())
                .andExpect(header().string(AgentConcurrency.HEADER, "1"))
                .andExpect(jsonPath("$.scanId").value(first));
        // Work is waiting, and the agent is at its limit: the answer is "nothing", not the scan.
        // And it costs no write — a waiting poll re-checks every second, and taking the agent's
        // row each time would be a write per second per agent sitting at its limit.
        Instant seenBefore = agents.findById(agent.id()).orElseThrow().getLastSeenAt();
        poll(agent).andExpect(status().isNoContent()).andExpect(header().string(AgentConcurrency.HEADER, "1"));
        assertThat(scans.findById(second).orElseThrow().getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(agents.findById(agent.id()).orElseThrow().getLastSeenAt()).isEqualTo(seenBefore);

        // Raised: the next poll takes the second scan, and says the new limit.
        change(agent.id(), "{\"max_concurrent\": 2}").andExpect(status().isOk());
        poll(agent).andExpect(status().isOk())
                .andExpect(header().string(AgentConcurrency.HEADER, "2"))
                .andExpect(jsonPath("$.scanId").value(second));

        long third = pending();
        poll(agent).andExpect(status().isNoContent());

        // A lease the agent stopped renewing is a scan nobody runs: it must not hold a slot until
        // the reclaim gets round to it.
        ScanEntity lapsed = scans.findById(first).orElseThrow();
        lapsed.setLeaseExpiresAt(Instant.now().minusSeconds(60));
        scans.save(lapsed);
        poll(agent).andExpect(status().isOk()).andExpect(jsonPath("$.scanId").value(third));

        // Lowered below what it holds: nothing new, and nothing already running is taken away.
        change(agent.id(), "{\"max_concurrent\": 1}").andExpect(status().isOk());
        pending();
        poll(agent).andExpect(status().isNoContent()).andExpect(header().string(AgentConcurrency.HEADER, "1"));
        assertThat(scans.findById(second).orElseThrow().getClaimedBy()).isEqualTo(agent.id().toString());
        assertThat(scans.findById(third).orElseThrow().getClaimedBy()).isEqualTo(agent.id().toString());
    }

    /** An image scan: its task needs a container row and nothing else — no key, no clone. */
    private long pending() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/service-" + System.nanoTime());
        image.setTag("1.0");
        long containerId = containers.save(image).getId();

        ScanEntity scan = new ScanEntity();
        scan.setContainerId(containerId);
        scan.setBranch("");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        return scans.save(scan).getId();
    }
}

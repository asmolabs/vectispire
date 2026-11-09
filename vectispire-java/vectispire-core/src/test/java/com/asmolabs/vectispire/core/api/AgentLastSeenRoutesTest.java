package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * When an agent counts as heard from — what the agents screen's "online" is read from.
 *
 * <p>Only the {@code hello} and a claim used to write it, so an agent polling every thirty seconds
 * and finding no work read as offline two minutes after its last claim, and one busy with a single
 * long scan read as offline for all of it. Through the routes, because the poll is a long-poll route
 * whose answer arrives by an asynchronous dispatch, and the heartbeat is the agent's own route.
 */
@DisplayName("an agent's last sign of life, through the routes")
class AgentLastSeenRoutesTest extends ApiTestBase {

    @Autowired
    private AgentRepository agents;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ContainerRepository containers;

    private record Enrolled(UUID id, String token) {}

    private Enrolled enrolled() throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"idle-" + System.nanoTime() + "\"}"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString());
        return new Enrolled(UUID.fromString(answer.get("id").asText()), answer.get("secret").asText());
    }

    private ResultActions poll(Enrolled agent) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent.token()))
                .andReturn();
        return mvc.perform(asyncDispatch(started));
    }

    private void lastSeen(Enrolled agent, Instant value) {
        AgentEntity row = agents.findById(agent.id()).orElseThrow();
        row.setLastSeenAt(value);
        agents.save(row);
    }

    private Instant lastSeen(Enrolled agent) {
        return agents.findById(agent.id()).orElseThrow().getLastSeenAt();
    }

    @Test
    @DisplayName("a poll that finds no work is a sign of life")
    void anIdlePollCounts() throws Exception {
        Enrolled agent = enrolled();
        lastSeen(agent, null);

        Instant before = Instant.now();
        poll(agent).andExpect(status().isNoContent());

        assertThat(lastSeen(agent)).isNotNull().isAfterOrEqualTo(before.minusMillis(1));

        // Two minutes of silence is what "offline" means; an agent that keeps polling is not silent.
        Instant stale = Instant.now().minus(Duration.ofMinutes(3));
        lastSeen(agent, stale);
        poll(agent).andExpect(status().isNoContent());
        assertThat(lastSeen(agent)).isAfter(stale.plus(Duration.ofMinutes(2)));
    }

    @Test
    @DisplayName("but a poll soon after another writes nothing: a fleet polling is not a write per poll")
    void aRecentSignIsNotRewritten() throws Exception {
        Enrolled agent = enrolled();
        Instant recent = Instant.now().minusSeconds(5).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        lastSeen(agent, recent);

        poll(agent).andExpect(status().isNoContent());

        assertThat(lastSeen(agent)).isEqualTo(recent);
    }

    @Test
    @DisplayName("a lease renewal is a sign of life: an agent busy with one long scan polls nothing")
    void aHeartbeatCounts() throws Exception {
        Enrolled agent = enrolled();
        long scan = pending();
        poll(agent).andExpect(status().isOk()).andExpect(jsonPath("$.scanId").value(scan));

        Instant stale = Instant.now().minus(Duration.ofMinutes(3));
        lastSeen(agent, stale);
        mvc.perform(post("/api/v1/agent/jobs/" + scan + "/heartbeat").header("Authorization", "Bearer " + agent.token()))
                .andExpect(status().isNoContent());

        assertThat(lastSeen(agent)).isAfter(stale.plus(Duration.ofMinutes(2)));
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

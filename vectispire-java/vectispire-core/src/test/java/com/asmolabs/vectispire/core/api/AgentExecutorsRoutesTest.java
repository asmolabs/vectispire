package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A worker claims a scan only when one of its executors can run it now, and the agents screen shows why.
 *
 * <p><b>The whole composition, on MySQL</b>: the hello's optional field reaching the row, the row reaching the
 * principal, the principal reaching the dispatcher's claim and the queue's selection, and the row reaching the
 * administration's list. Each half has its unit test; this is the only level at which a field the hello reads and
 * nothing writes — or one the row holds and the claim never asks — is visible.
 *
 * <p><b>The previous agent is the first case, not an afterthought</b> (decision 0043 §2): a hello that says
 * nothing about executors must leave the agent claiming exactly as before. The {@code previous-agent} CI job runs
 * the released agent itself against this control plane; this is the same promise at the route.
 */
@DisplayName("a worker's executors, the claim, and the agents screen")
class AgentExecutorsRoutesTest extends ApiTestBase {

    private static final Map<String, Object> DOCKER_DOWN = Map.of(
            "kind", "docker", "available", false, "targets", List.of("repository", "container"),
            "detail", "The Docker daemon did not answer a ping: connection refused");
    private static final Map<String, Object> DOCKER_UP = Map.of(
            "kind", "docker", "available", true, "targets", List.of("repository", "container"));
    private static final Map<String, Object> KUBERNETES_UP = Map.of(
            "kind", "kubernetes", "available", true, "targets", List.of("repository"));

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ContainerRepository containers;

    private String enrolled(String name) throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"" + name + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        return answer.get("secret").asText();
    }

    /** The hello an agent of this version sends, or — with no executors — the one a 0.11 agent sends. */
    private void hello(String token, List<Map<String, Object>> executors) throws Exception {
        Map<String, Object> body = new java.util.LinkedHashMap<>(Map.of(
                "contract_version", "1", "hostname", "edge-1", "platform", "Linux", "scanner_engine", "docker"));
        if (executors != null) {
            body.put("executors", executors);
        }
        mvc.perform(post("/api/v1/agent/hello").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isOk());
    }

    private ResultActions report(String token, Object body) throws Exception {
        return mvc.perform(put("/api/v1/agent/executors").header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private ResultActions poll(String token) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + token))
                .andReturn();
        return mvc.perform(asyncDispatch(started));
    }

    private ResultActions listed() throws Exception {
        return mvc.perform(authenticated(get("/api/v1/admin/agents"), asAdmin())).andExpect(status().isOk());
    }

    @Test
    @DisplayName("an agent that announces no executors claims as before, and the screen says it never said")
    void anOldAgentClaimsAsBefore() throws Exception {
        String token = enrolled("previous");
        hello(token, null);
        long scan = pendingImageScan();

        poll(token).andExpect(status().isOk()).andExpect(jsonPath("$.scanId").value(scan));
        listed().andExpect(jsonPath("$[0].executors").doesNotExist())
                .andExpect(jsonPath("$[0].executorsReportedAt").doesNotExist());
    }

    @Test
    @DisplayName("an agent whose executor is down claims nothing, the screen shows why, and a report brings it back")
    void anUnavailableExecutorClaimsNothing() throws Exception {
        String token = enrolled("edge");
        hello(token, List.of(DOCKER_DOWN));
        long scan = pendingImageScan();

        poll(token).andExpect(status().isNoContent());
        assertThat(scans.findById(scan).orElseThrow().getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        listed().andExpect(jsonPath("$[0].executors[0].kind").value("docker"))
                .andExpect(jsonPath("$[0].executors[0].available").value(false))
                .andExpect(jsonPath("$[0].executors[0].targets[1]").value("container"))
                .andExpect(jsonPath("$[0].executors[0].detail").value(org.hamcrest.Matchers.containsString("ping")))
                .andExpect(jsonPath("$[0].executorsReportedAt").exists());
        mvc.perform(authenticated(get("/api/v1/admin/agents/activity"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pendingScans[0].scanId").value(scan))
                .andExpect(jsonPath("$.pendingScans[0].executorAvailable").value(false));

        report(token, Map.of("executors", List.of(DOCKER_UP))).andExpect(status().isNoContent());

        listed().andExpect(jsonPath("$[0].executors[0].available").value(true))
                .andExpect(jsonPath("$[0].executors[0].detail").doesNotExist());
        mvc.perform(authenticated(get("/api/v1/admin/agents/activity"), asAdmin()))
                .andExpect(jsonPath("$.pendingScans[0].executorAvailable").value(true));
        poll(token).andExpect(status().isOk()).andExpect(jsonPath("$.scanId").value(scan));
    }

    @Test
    @DisplayName("a Kubernetes agent is not handed an image scan, which its executor cannot run")
    void anExecutorClaimsOnlyItsKinds() throws Exception {
        String token = enrolled("cluster");
        hello(token, List.of(KUBERNETES_UP));
        long scan = pendingImageScan();

        poll(token).andExpect(status().isNoContent());
        assertThat(scans.findById(scan).orElseThrow().getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
    }

    @Test
    @DisplayName("a hello without executors after one with them puts the agent back to unknown, claiming as before")
    void aDowngradedAgentIsUnknownAgain() throws Exception {
        String token = enrolled("rolled-back");
        hello(token, List.of(DOCKER_DOWN));
        hello(token, null);
        long scan = pendingImageScan();

        listed().andExpect(jsonPath("$[0].executors").doesNotExist());
        poll(token).andExpect(status().isOk()).andExpect(jsonPath("$.scanId").value(scan));
    }

    @Test
    @DisplayName("a report needs a list and an agent's key; an empty list is an agent with no executor")
    void theReportRoute() throws Exception {
        String token = enrolled("strict");
        hello(token, null);

        report(token, Map.of()).andExpect(status().isBadRequest());
        mvc.perform(put("/api/v1/agent/executors").contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("executors", List.of()))))
                .andExpect(status().isUnauthorized());
        mvc.perform(authenticated(put("/api/v1/agent/executors"), asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("executors", List.of()))))
                .andExpect(status().isUnauthorized());

        report(token, Map.of("executors", List.of())).andExpect(status().isNoContent());
        pendingImageScan();
        listed().andExpect(jsonPath("$[0].executors").isEmpty());
        poll(token).andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("the built-in worker's state answers, here a control plane that scans nothing itself")
    void theBuiltInWorker() throws Exception {
        mvc.perform(authenticated(get("/api/v1/admin/agents/built-in-worker"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.runsScans").value(false))
                .andExpect(jsonPath("$.executors").isEmpty())
                .andExpect(jsonPath("$.checkedAt").doesNotExist());
        mvc.perform(authenticated(get("/api/v1/admin/agents/built-in-worker"), asReader()))
                .andExpect(status().isForbidden());
    }

    /** An image scan: its task needs a container row and nothing else — no key, no clone. */
    private long pendingImageScan() {
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

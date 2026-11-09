package com.asmolabs.vectispire.core.api;

import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.GROUPS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.PROJECTS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.TOKEN;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.project;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryWorker;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

/**
 * A discovery's bounds (decision 0037 §3, answer 8), each reached in seconds: three repositories instead of twenty
 * thousand, three seconds instead of thirty minutes, a one-second rate-limit wait instead of a minute — read from
 * the configuration the application reads, so that what is pinned is the run's handling of a bound, not a
 * constant. Past each the run ends partial, keeps what it read, and marks nothing gone.
 */
@TestPropertySource(properties = {
    "vectispire.forges.discovery.max-repositories=3",
    "vectispire.forges.discovery.max-duration=3s",
    "vectispire.forges.discovery.max-rate-limit-wait=1s"
})
@DisplayName("forge discoveries, at their bounds")
class ForgeDiscoveryBoundsRoutesTest extends ApiTestBase {

    @Autowired
    private DiscoveryWorker worker;

    @Autowired
    private ForgeRepositoryRepository snapshot;

    private ForgeStub gitlab;

    @BeforeEach
    void start() throws Exception {
        gitlab = ForgeStub.start().gitlab("17.4.1-ee", "[\"read_api\"]", true);
        gitlab.route(GROUPS, Reply.json("[{\"id\":1,\"full_path\":\"acme\"}]"));
    }

    @AfterEach
    void stop() {
        gitlab.close();
    }

    private String connection() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Internal GitLab");
        body.put("kind", "gitlab");
        body.put("baseUrl", gitlab.baseUrl());
        body.put("internalNetwork", true);
        body.put("caPem", gitlab.caPem);
        body.put("token", TOKEN);
        return json.readTree(mvc.perform(authenticated(post("/api/v1/forge-connections"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).at("/id").asText();
    }

    private JsonNode discover(String connectionId) throws Exception {
        long id = json.readTree(mvc.perform(authenticated(post("/api/v1/forge-connections/" + connectionId
                        + "/discoveries"), asAdmin())).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString()).at("/id").asLong();
        worker.drain();
        return json.readTree(mvc.perform(authenticated(get("/api/v1/forge-connections/" + connectionId + "/discoveries/"
                + id), asAdmin())).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    /** Keyset pages of the projects given, by id; each page after the first named by the previous one's Link. */
    private void projects(List<List<Integer>> pages) {
        for (int page = 0; page < pages.size(); page++) {
            String path = page == 0 ? PROJECTS : PROJECTS + "&id_after=" + page;
            List<String> listed = pages.get(page).stream()
                    .map(id -> project(id, "acme/p" + id, "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))
                    .toList();
            Reply reply = Reply.json("[" + String.join(",", listed) + "]");
            if (page + 1 < pages.size()) {
                reply = reply.with("Link", "<" + gitlab.baseUrl() + PROJECTS + "&id_after=" + (page + 1) + ">; rel=\"next\"");
            }
            gitlab.route(path, reply);
        }
    }

    @Test
    @DisplayName("past the repository bound: what fitted is kept, the rest unread, and what was not reached is not gone")
    void theRepositoryBound() throws Exception {
        String connectionId = connection();
        projects(List.of(List.of(50, 51)));
        assertThat(discover(connectionId).at("/state").asText()).isEqualTo("completed");

        projects(List.of(List.of(10, 11), List.of(12, 50), List.of(51)));
        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("partial");
        assertThat(run.at("/reason").asText()).isEqualTo("repository_bound");
        assertThat(run.at("/repositoriesSeen").asInt()).isEqualTo(3);
        assertThat(run.at("/newCount").asInt()).isEqualTo(3);
        assertThat(run.at("/goneCount").isNull()).isTrue();
        assertThat(gitlab.count(PROJECTS + "&id_after=2")).as("the page past the bound is never asked").isZero();
        assertThat(snapshot.findAll()).hasSize(5).allSatisfy(row -> assertThat(row.getGoneBy()).isNull());
    }

    @Test
    @DisplayName("exactly at the bound the listing ends complete")
    void atTheBound() throws Exception {
        String connectionId = connection();
        projects(List.of(List.of(10, 11), List.of(12)));

        JsonNode run = discover(connectionId);
        assertThat(run.at("/state").asText()).isEqualTo("completed");
        assertThat(run.at("/repositoriesSeen").asInt()).isEqualTo(3);
    }

    @Test
    @DisplayName("past the time bound the run ends partial, between two pages")
    void theTimeBound() throws Exception {
        String connectionId = connection();
        projects(List.of(List.of(10), List.of(11), List.of(12)));
        gitlab.slow(PROJECTS, Duration.ofMillis(1700));
        gitlab.slow(PROJECTS + "&id_after=1", Duration.ofMillis(1700));

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("partial");
        assertThat(run.at("/reason").asText()).isEqualTo("time_bound");
        assertThat(run.at("/repositoriesSeen").asInt()).isEqualTo(2);
        assertThat(gitlab.count(PROJECTS + "&id_after=2")).isZero();
    }

    @Test
    @DisplayName("a rate limit longer than the wait bound is not slept: partial, rate_limited")
    void theWaitBound() throws Exception {
        String connectionId = connection();
        projects(List.of(List.of(10)));
        gitlab.sequence(PROJECTS, Reply.status(429).with("Retry-After", "2"));

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("partial");
        assertThat(run.at("/reason").asText()).isEqualTo("rate_limited");
        assertThat(run.at("/rateLimitWaitSeconds").asLong()).isZero();
        assertThat(gitlab.count(PROJECTS)).isOne();
    }
}

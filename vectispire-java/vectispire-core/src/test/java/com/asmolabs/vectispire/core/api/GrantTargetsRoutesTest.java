package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * A grant names a target that exists — for an account and for a team, and for every kind.
 *
 * <p>Only a project was checked. A repository or an image id was stored whatever it was: listed as
 * "deleted target", granting nothing, and waiting for the identifier to be handed out again.
 */
@DisplayName("what a grant may name")
class GrantTargetsRoutesTest extends ApiTestBase {

    /** Well past anything the suite creates, and never handed out: the engines do not reuse ids. */
    private static final long ABSENT = 987_654_321L;

    @Autowired
    private UserRepository users;

    @Autowired
    private UserTargetRepository userTargets;

    @Autowired
    private TeamTargetRepository teamTargets;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Test
    @DisplayName("an account granted a repository or an image that does not exist is a 404, and keeps what it held")
    void anAccountGrantOnAnAbsentTargetIsRefused() throws Exception {
        long account = account("grant-absent");
        long repository = repository();
        assertThat(grant("/api/v1/users/" + account, List.of(Map.of("kind", "repository", "id", repository))).getStatus())
                .isEqualTo(200);

        for (String kind : new String[] {"repository", "container"}) {
            MockHttpServletResponse refused = grant("/api/v1/users/" + account,
                    List.of(Map.of("kind", "repository", "id", repository), Map.of("kind", kind, "id", ABSENT)));

            assertThat(refused.getStatus()).as(kind).isEqualTo(404);
            assertThat(json.readTree(refused.getContentAsString()).path("detail").asText())
                    .isEqualTo("No " + kind + " with id " + ABSENT + ".");
        }
        assertThat(userTargets.findByUserId(account))
                .as("the replacement is refused whole")
                .extracting(row -> row.getId().targetKind() + ":" + row.getId().targetId())
                .containsExactly("repository:" + repository);
    }

    @Test
    @DisplayName("a team granted a repository or an image that does not exist is a 404, and keeps what it held")
    void aTeamGrantOnAnAbsentTargetIsRefused() throws Exception {
        long team = team("grant-absent-" + System.nanoTime());
        long image = container();
        assertThat(grant("/api/v1/teams/" + team, List.of(Map.of("kind", "container", "id", image))).getStatus())
                .isEqualTo(200);

        for (String kind : new String[] {"repository", "container"}) {
            MockHttpServletResponse refused = grant("/api/v1/teams/" + team,
                    List.of(Map.of("kind", "container", "id", image), Map.of("kind", kind, "id", ABSENT)));

            assertThat(refused.getStatus()).as(kind).isEqualTo(404);
            assertThat(json.readTree(refused.getContentAsString()).path("detail").asText())
                    .isEqualTo("No " + kind + " with id " + ABSENT + ".");
        }
        assertThat(teamTargets.findByTeamId(team))
                .extracting(row -> row.getId().targetKind() + ":" + row.getId().targetId())
                .containsExactly("container:" + image);
    }

    @Test
    @DisplayName("a grant already held is kept when its target has gone, so the set stays editable; a new one is not")
    void aGrantAlreadyHeldIsKept() throws Exception {
        // A row left by a deletion from before grants were revoked with their target: the screen lists
        // it as "deleted target" and sends it back with every edit.
        long account = account("grant-held");
        userTargets.save(new UserTargetEntity(account, "repository", ABSENT));
        long team = team("grant-held-" + System.nanoTime());
        teamTargets.save(new TeamTargetEntity(team, "container", ABSENT));
        long repository = repository();

        assertThat(grant("/api/v1/users/" + account, List.of(
                        Map.of("kind", "repository", "id", ABSENT), Map.of("kind", "repository", "id", repository)))
                .getStatus()).isEqualTo(200);
        assertThat(userTargets.findByUserId(account)).hasSize(2);
        assertThat(grant("/api/v1/teams/" + team, List.of(
                        Map.of("kind", "container", "id", ABSENT), Map.of("kind", "repository", "id", repository)))
                .getStatus()).isEqualTo(200);
        assertThat(teamTargets.findByTeamId(team)).hasSize(2);

        // Held as a repository, not as an image: the pair is the grant.
        assertThat(grant("/api/v1/users/" + account, List.of(Map.of("kind", "container", "id", ABSENT))).getStatus())
                .isEqualTo(404);
    }

    private MockHttpServletResponse grant(String grantee, List<Map<String, Object>> body) throws Exception {
        return mvc.perform(authenticated(put(grantee + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse();
    }

    private long account(String username) {
        tokenFor(username, Role.USER, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private long team(String name) throws Exception {
        return json.readTree(mvc.perform(authenticated(post("/api/v1/teams"), asAdmin())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", name))))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString())
                .get("id").asLong();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/granted-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/granted-" + System.nanoTime());
        image.setTag("latest");
        return containers.save(image).getId();
    }
}

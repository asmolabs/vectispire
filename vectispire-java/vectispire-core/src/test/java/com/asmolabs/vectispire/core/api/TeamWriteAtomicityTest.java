package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * A team's replacement or deletion is one gesture or none.
 *
 * <p><b>Why this exists.</b> Each repository call of {@code TeamAdministrationService} committed
 * alone: the members were deleted, then the new ones inserted, so a failure in between left the
 * team with nobody in it — and a deletion that failed half-way left a team without its members but
 * still standing. The account's grants were made atomic for that reason
 * ({@code AccountAdminService.replaceTargets}); the team's were not. As in
 * {@link AccountRevocationAtomicityTest}, the second write is made to fail, and the question is
 * whether the first survived.
 */
@DisplayName("a team write that fails half-way")
class TeamWriteAtomicityTest extends ApiTestBase {

    @MockitoSpyBean
    private TeamMemberRepository members;

    @MockitoSpyBean
    private TeamTargetRepository targets;

    @MockitoSpyBean
    private TeamWebhookRepository webhooks;

    @Autowired
    private TeamRepository teams;

    @Autowired
    private UserRepository users;

    @Autowired
    private GitRepositoryRepository repositories;

    @Test
    @DisplayName("keeps the members it was replacing")
    void keepsTheMembers() throws Exception {
        long team = team();
        long kept = account("kept");
        long added = account("added");
        replace(team, "members", List.of(kept)).andExpect(status().isOk());

        doThrow(new QueryTimeoutException("lock wait timeout on t_team_member"))
                .when(members)
                .save(argThat((TeamMemberEntity row) -> row != null && row.getId().userId().equals(added)));

        assertThat(replace(team, "members", List.of(added)).andReturn().getResponse().getStatus()).isEqualTo(500);
        assertThat(members.findByTeamId(team))
                .as("the delete must roll back with the insert that failed")
                .extracting(row -> row.getId().userId())
                .containsExactly(kept);
    }

    @Test
    @DisplayName("keeps the targets it was replacing")
    void keepsTheTargets() throws Exception {
        long team = team();
        long kept = repository();
        long added = repository();
        replace(team, "targets", List.of(Map.of("kind", "repository", "id", kept))).andExpect(status().isOk());

        doThrow(new QueryTimeoutException("lock wait timeout on t_team_target"))
                .when(targets)
                .save(argThat((TeamTargetEntity row) -> row != null && row.getId().targetId().equals(added)));

        assertThat(replace(team, "targets", List.of(Map.of("kind", "repository", "id", added)))
                        .andReturn().getResponse().getStatus())
                .isEqualTo(500);
        assertThat(targets.findByTeamId(team))
                .extracting(row -> row.getId().targetId())
                .containsExactly(kept);
    }

    @Test
    @DisplayName("leaves a team it could not delete whole")
    void leavesTheTeamWhole() throws Exception {
        long team = team();
        long member = account("member");
        replace(team, "members", List.of(member)).andExpect(status().isOk());

        doThrow(new QueryTimeoutException("lock wait timeout on t_team_webhook")).when(webhooks).deleteById(eq(team));

        assertThat(mvc.perform(authenticated(delete("/api/v1/teams/" + team), asAdmin()))
                        .andReturn().getResponse().getStatus())
                .isEqualTo(500);
        assertThat(teams.findById(team)).isPresent();
        assertThat(members.findByTeamId(team))
                .as("a team still standing keeps its members, or every one of them silently lost its grants")
                .hasSize(1);
    }

    private org.springframework.test.web.servlet.ResultActions replace(long team, String what, Object body)
            throws Exception {
        return mvc.perform(authenticated(put("/api/v1/teams/" + team + "/" + what), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)));
    }

    private long team() throws Exception {
        return json.readTree(mvc.perform(authenticated(post("/api/v1/teams"), asAdmin())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", "atomic-" + System.nanoTime()))))
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString())
                .get("id").asLong();
    }

    private long account(String prefix) {
        String username = prefix + "-" + System.nanoTime();
        tokenFor(username, Role.USER, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/atomic-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}

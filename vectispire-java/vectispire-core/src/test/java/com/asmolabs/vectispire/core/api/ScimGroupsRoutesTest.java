package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLog;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The SCIM group routes, reads and writes.
 *
 * <p><b>The writes could not be tested here until the audit entry left the transaction.</b> Each
 * group write recorded its entry inside its own transaction, in the audit's {@code REQUIRES_NEW}
 * one, and on the SQLite fixture that second connection waited on the first one's lock on the
 * file: every write answered {@code SQLITE_BUSY}. Each case below therefore asserts the audit entry
 * as well as the effect — the entry is the part that used to deadlock.
 *
 * <p>PATCH is sent as the directory sends it, JSON through the real message converter: the body's
 * {@code value} failed to deserialize at that layer, and only a request crossing it could say so.
 */
@DisplayName("the SCIM group routes")
class ScimGroupsRoutesTest extends ApiTestBase {

    private static final MediaType SCIM = MediaType.parseMediaType("application/scim+json");

    @Autowired
    private Teams teams;

    @Autowired
    private TeamMembers members;

    @Autowired
    private Users users;

    @Autowired
    private AuditLog auditLogs;

    @Test
    @DisplayName("list and read a group with its members, and answer 404 for one that is not there")
    void readsGroups() throws Exception {
        long userId = account("scim-member");
        long id = team("Platform");
        members.save(new TeamMemberEntity(id, userId, TeamMemberEntity.Origin.SCIM));

        mvc.perform(authenticated(get("/scim/v2/Groups/" + id), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(String.valueOf(id)))
                .andExpect(jsonPath("$.displayName").value("Platform"))
                .andExpect(jsonPath("$.members[0].value").value(String.valueOf(userId)))
                .andExpect(jsonPath("$.members[0].display").value("scim-member"))
                .andExpect(jsonPath("$.meta.location").value("/scim/v2/Groups/" + id));

        mvc.perform(authenticated(get("/scim/v2/Groups"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalResults").value(1));

        mvc.perform(authenticated(get("/scim/v2/Groups/" + (id + 1000)), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("create a group with its members, marked as SCIM's, and refuse a name already taken")
    void createsGroup() throws Exception {
        long userId = account("scim-alice");

        mvc.perform(authenticated(post("/scim/v2/Groups"), asAdmin())
                        .contentType(SCIM)
                        .content(write(Map.of(
                                "displayName", "Payments",
                                "members", List.of(Map.of("value", "scim-alice"))))))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", org.hamcrest.Matchers.startsWith("/scim/v2/Groups/")))
                .andExpect(jsonPath("$.displayName").value("Payments"))
                .andExpect(jsonPath("$.members[0].value").value(String.valueOf(userId)));

        TeamEntity created = teams.findByNameIgnoreCase("Payments").orElseThrow();
        assertThat(members.findByTeamId(created.getId()))
                .singleElement()
                .satisfies(member -> {
                    assertThat(member.getId().userId()).isEqualTo(userId);
                    // The mark is what keeps the OIDC reconciliation from carrying it away.
                    assertThat(member.getOrigin()).isEqualTo(TeamMemberEntity.Origin.SCIM);
                });
        assertAudited("SCIM created team: Payments");

        mvc.perform(authenticated(post("/scim/v2/Groups"), asAdmin())
                        .contentType(SCIM)
                        .content(write(Map.of("displayName", "payments"))))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("replace a group's name and its whole membership")
    void replacesGroup() throws Exception {
        long leaving = account("scim-leaving");
        long joining = account("scim-joining");
        long id = team("Platform");
        members.save(new TeamMemberEntity(id, leaving, TeamMemberEntity.Origin.SCIM));

        mvc.perform(authenticated(put("/scim/v2/Groups/" + id), asAdmin())
                        .contentType(SCIM)
                        .content(write(Map.of(
                                "displayName", "Platform Engineering",
                                "members", List.of(Map.of("value", String.valueOf(joining)))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.displayName").value("Platform Engineering"))
                .andExpect(jsonPath("$.members.length()").value(1))
                .andExpect(jsonPath("$.members[0].value").value(String.valueOf(joining)));

        // Read back from the row, not from the response: the response had the new name all along
        // while the membership rewrite discarded the rename before it reached the database.
        assertThat(teams.findById(id).orElseThrow().getName()).isEqualTo("Platform Engineering");
        assertThat(members.findByTeamId(id))
                .extracting(member -> member.getId().userId())
                .containsExactly(joining);
        assertAudited("SCIM updated team: Platform Engineering");

        mvc.perform(authenticated(put("/scim/v2/Groups/" + (id + 1000)), asAdmin())
                        .contentType(SCIM)
                        .content(write(Map.of("displayName", "Nobody"))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("patch a group: add a member, then remove one")
    void patchesGroup() throws Exception {
        long kept = account("scim-kept");
        long added = account("scim-added");
        long id = team("Security");
        members.save(new TeamMemberEntity(id, kept, TeamMemberEntity.Origin.SCIM));

        mvc.perform(authenticated(patch("/scim/v2/Groups/" + id), asAdmin())
                        .contentType(SCIM)
                        .content(write(Map.of("Operations", List.of(Map.of(
                                "op", "add",
                                "path", "members",
                                "value", List.of(Map.of("value", String.valueOf(added)))))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(2));

        assertThat(members.findByTeamId(id))
                .extracting(member -> member.getId().userId())
                .containsExactlyInAnyOrder(kept, added);

        mvc.perform(authenticated(patch("/scim/v2/Groups/" + id), asAdmin())
                        .contentType(SCIM)
                        .content(write(Map.of("Operations", List.of(Map.of(
                                "op", "remove",
                                "path", "members[value eq \"" + kept + "\"]"))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.members.length()").value(1));

        assertThat(members.findByTeamId(id))
                .extracting(member -> member.getId().userId())
                .containsExactly(added);
        assertThat(auditLogs.findAll())
                .filteredOn(entry -> "SCIM patched team: Security".equals(entry.getDescription()))
                .hasSize(2);
    }

    @Test
    @DisplayName("delete a group and its memberships, and answer 204 again for one already gone")
    void deletesGroup() throws Exception {
        long userId = account("scim-member");
        long id = team("Retired");
        members.save(new TeamMemberEntity(id, userId, TeamMemberEntity.Origin.SCIM));

        mvc.perform(authenticated(delete("/scim/v2/Groups/" + id), asAdmin()))
                .andExpect(status().isNoContent());

        assertThat(teams.findById(id)).isEmpty();
        assertThat(members.findByTeamId(id)).isEmpty();
        assertAudited("SCIM deleted team: Retired");

        // Idempotent, as RFC 7644 allows — and nothing changed, so nothing more is recorded.
        long before = auditLogs.count();
        mvc.perform(authenticated(delete("/scim/v2/Groups/" + id), asAdmin()))
                .andExpect(status().isNoContent());
        assertThat(auditLogs.count()).isEqualTo(before);
    }

    private long account(String username) {
        tokenFor(username, Role.USER, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private long team(String name) {
        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setCreatedAt(Instant.now());
        return teams.save(team).getId();
    }

    private void assertAudited(String description) {
        assertThat(auditLogs.findAll())
                .anySatisfy(entry -> {
                    assertThat(entry.getDescription()).isEqualTo(description);
                    assertThat(entry.getOperationType()).isEqualTo(AuditOperation.TEAM_UPDATED.name());
                    assertThat(entry.getResourceId()).isEqualTo("SCIM");
                });
    }
}

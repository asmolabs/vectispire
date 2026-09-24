package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The SCIM group reads, through the routes.
 *
 * <p><b>The writes are not here, and not by choice.</b> Each group write runs in one transaction
 * and records its audit entry inside it, in the audit's own {@code REQUIRES_NEW} transaction. On
 * the SQLite fixture that second connection waits on the first one's lock on the file, and the
 * request fails with {@code SQLITE_BUSY}. It did so as well when the boundary sat on the
 * controller, before it moved into {@code ScimProvisioningService}. A write test belongs here once
 * the audit entry is recorded outside the boundary, as {@code AgentAdministrationService} does.
 */
@DisplayName("the SCIM group routes")
class ScimGroupsRoutesTest extends ApiTestBase {

    @Autowired
    private Teams teams;

    @Autowired
    private TeamMembers members;

    @Autowired
    private Users users;

    @Test
    @DisplayName("list and read a group with its members, and answer 404 for one that is not there")
    void readsGroups() throws Exception {
        tokenFor("scim-member", Role.USER, false);
        long userId = users.findByUsername("scim-member").orElseThrow().getId();

        TeamEntity team = new TeamEntity();
        team.setName("Platform");
        team.setCreatedAt(Instant.now());
        long id = teams.save(team).getId();
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
}

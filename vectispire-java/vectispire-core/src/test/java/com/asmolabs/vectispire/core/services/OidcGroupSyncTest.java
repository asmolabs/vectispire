package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OIDC Group Sync")
class OidcGroupSyncTest {

    private Users users;
    private Teams teams;
    private TeamMembers teamMembers;
    private ExternalIdentityService service;

    @BeforeEach
    void setUp() {
        users = mock(Users.class);
        teams = mock(Teams.class);
        teamMembers = mock(TeamMembers.class);
        service = new ExternalIdentityService(users, Optional.of(teams), Optional.of(teamMembers));
    }

    @Test
    @DisplayName("assigns user to matching team when OIDC groups are received")
    void syncsGroupMembership() {
        UserEntity user = new UserEntity();
        user.setId(10L);
        user.setUsername("david");
        user.setIsActive(true);

        TeamEntity secTeam = new TeamEntity();
        secTeam.setId(5L);
        secTeam.setName("AppSec");

        when(teams.findByNameIgnoreCase("AppSec")).thenReturn(Optional.of(secTeam));
        when(teamMembers.existsById(new TeamMemberEntity.Id(5L, 10L))).thenReturn(false);

        service.syncGroups(user, List.of("AppSec"));

        verify(teamMembers).save(any(TeamMemberEntity.class));
    }

    @Test
    @DisplayName("does not re-add existing team membership")
    void skipsExistingMembership() {
        UserEntity user = new UserEntity();
        user.setId(10L);
        user.setUsername("david");
        user.setIsActive(true);

        TeamEntity secTeam = new TeamEntity();
        secTeam.setId(5L);
        secTeam.setName("AppSec");

        when(teams.findByNameIgnoreCase("AppSec")).thenReturn(Optional.of(secTeam));
        when(teamMembers.existsById(new TeamMemberEntity.Id(5L, 10L))).thenReturn(true);

        service.syncGroups(user, List.of("AppSec"));

        verify(teamMembers, never()).save(any(TeamMemberEntity.class));
    }
}

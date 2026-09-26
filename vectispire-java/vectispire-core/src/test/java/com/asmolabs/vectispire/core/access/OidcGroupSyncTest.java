package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMembers;
import com.asmolabs.vectispire.core.access.persistence.Teams;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.Users;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Reconciling teams from the directory.
 *
 * <p><b>Three ways of getting it wrong, and only one of them is loud.</b> Failing to add shows at
 * the first sign-in. Failing to remove never shows — that was the original behaviour, and it made
 * the promise that leaving a group revokes an access untenable. Removing <em>too much</em> shows
 * only afterwards, when an administrator's assignments have vanished without anybody doing
 * anything. Each case below aims at one of the three.
 */
@DisplayName("la synchronisation des groupes OIDC")
class OidcGroupSyncTest {

    private Teams teams;
    private TeamMembers teamMembers;
    private ExternalIdentityService service;
    private UserEntity user;

    @BeforeEach
    void setUp() {
        teams = mock(Teams.class);
        teamMembers = mock(TeamMembers.class);
        service = new ExternalIdentityService(mock(Users.class), Optional.of(teams), Optional.of(teamMembers), false);

        user = new UserEntity();
        user.setId(10L);
        user.setUsername("david");
        user.setIsActive(true);
    }

    private void teamNamed(String name, long id) {
        TeamEntity team = new TeamEntity();
        team.setId(id);
        team.setName(name);
        when(teams.findByNameIgnoreCase(name)).thenReturn(Optional.of(team));
    }

    private void alreadyIn(TeamMemberEntity... memberships) {
        when(teamMembers.findByUserId(10L)).thenReturn(new ArrayList<>(List.of(memberships)));
    }

    private TeamMemberEntity saved() {
        ArgumentCaptor<TeamMemberEntity> captor = ArgumentCaptor.forClass(TeamMemberEntity.class);
        verify(teamMembers).save(captor.capture());
        return captor.getValue();
    }

    @Test
    @DisplayName("a claimed team is joined, and marked as coming from the directory")
    void joinsAClaimedTeam() {
        teamNamed("AppSec", 5L);
        alreadyIn();

        service.syncGroups(UserView.of(user), List.of("AppSec"));

        assertThat(saved().getId()).isEqualTo(new TeamMemberEntity.Id(5L, 10L));
        assertThat(saved().getOrigin())
                .as("without this mark, reconciliation would not know which rows are its own")
                .isEqualTo(TeamMemberEntity.Origin.OIDC);
    }

    @Test
    @DisplayName("a membership already held is not rewritten")
    void doesNotRewriteWhatIsAlreadyHeld() {
        teamNamed("AppSec", 5L);
        alreadyIn(new TeamMemberEntity(5L, 10L, TeamMemberEntity.Origin.OIDC));

        service.syncGroups(UserView.of(user), List.of("AppSec"));

        verify(teamMembers, never()).save(any(TeamMemberEntity.class));
    }

    @Test
    @DisplayName("a group left in the directory removes the team here")
    void leavingAGroupRevokesTheTeam() {
        // **The case this phase exists for.** The method only ever added: removing somebody from a
        // group took away neither the team nor the visibility that comes with it, although that is
        // the very reason for delegating.
        teamNamed("AppSec", 5L);
        TeamMemberEntity gone = new TeamMemberEntity(9L, 10L, TeamMemberEntity.Origin.OIDC);
        alreadyIn(new TeamMemberEntity(5L, 10L, TeamMemberEntity.Origin.OIDC), gone);

        service.syncGroups(UserView.of(user), List.of("AppSec"));

        verify(teamMembers).delete(gone);
    }

    @Test
    @DisplayName("what an administrator assigned survives the sign-in")
    void neverTouchesAManualAssignment() {
        // **The trap on the other side.** Reconciling everything would have silently erased, at
        // every sign-in, the teams assigned by hand — a worse defect than the one being fixed.
        teamNamed("AppSec", 5L);
        TeamMemberEntity byHand = new TeamMemberEntity(7L, 10L, TeamMemberEntity.Origin.MANUAL);
        TeamMemberEntity byScim = new TeamMemberEntity(8L, 10L, TeamMemberEntity.Origin.SCIM);
        alreadyIn(byHand, byScim);

        service.syncGroups(UserView.of(user), List.of("AppSec"));

        verify(teamMembers, never()).delete(byHand);
        verify(teamMembers, never()).delete(byScim);
    }

    @Test
    @DisplayName("an empty claim revokes nothing")
    void anEmptyClaimIsNotARevocation() {
        // A forgotten mapper, a token without the claim: an absence of groups is a configuration
        // failure, not "this person is no longer in any team". Revoking on that basis would cut
        // everybody off at the first missed setting.
        alreadyIn(new TeamMemberEntity(5L, 10L, TeamMemberEntity.Origin.OIDC));

        service.syncGroups(UserView.of(user), List.of());
        service.syncGroups(UserView.of(user), null);

        verify(teamMembers, never()).delete(any(TeamMemberEntity.class));
    }

    @Test
    @DisplayName("a group with no matching team is not an error")
    void anUnknownGroupIsIgnored() {
        // L'annuaire d'une organisation est plus large que ce que cet outil suit.
        when(teams.findByNameIgnoreCase("Comptabilité")).thenReturn(Optional.empty());
        alreadyIn();

        service.syncGroups(UserView.of(user), List.of("Comptabilité"));

        verify(teamMembers, never()).save(any(TeamMemberEntity.class));
        verify(teamMembers, never()).delete(any(TeamMemberEntity.class));
    }
}

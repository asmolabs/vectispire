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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * La réconciliation des équipes depuis l'annuaire.
 *
 * <p><b>Trois façons de se tromper, et une seule est bruyante.</b> Ne pas ajouter se voit à la
 * première connexion. Ne pas retirer ne se voit jamais — c'était le comportement d'origine, et il
 * rendait intenable la promesse qu'un départ de groupe révoque un accès. Retirer <em>trop</em> ne
 * se voit qu'après coup, quand les affectations d'un administrateur ont disparu sans que personne
 * n'ait rien fait. Chaque cas ci-dessous vise l'une des trois.
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
        service = new ExternalIdentityService(mock(Users.class), Optional.of(teams), Optional.of(teamMembers));

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
    @DisplayName("une équipe revendiquée est rejointe, et marquée comme venant de l'annuaire")
    void joinsAClaimedTeam() {
        teamNamed("AppSec", 5L);
        alreadyIn();

        service.syncGroups(user, List.of("AppSec"));

        assertThat(saved().getId()).isEqualTo(new TeamMemberEntity.Id(5L, 10L));
        assertThat(saved().getOrigin())
                .as("sans cette marque, la réconciliation ne saurait pas quelles lignes sont les siennes")
                .isEqualTo(TeamMemberEntity.Origin.OIDC);
    }

    @Test
    @DisplayName("une appartenance déjà tenue n'est pas réécrite")
    void doesNotRewriteWhatIsAlreadyHeld() {
        teamNamed("AppSec", 5L);
        alreadyIn(new TeamMemberEntity(5L, 10L, TeamMemberEntity.Origin.OIDC));

        service.syncGroups(user, List.of("AppSec"));

        verify(teamMembers, never()).save(any(TeamMemberEntity.class));
    }

    @Test
    @DisplayName("un groupe quitté dans l'annuaire retire l'équipe ici")
    void leavingAGroupRevokesTheTeam() {
        // **Le cas pour lequel cette phase existe.** La méthode n'ajoutait que : retirer quelqu'un
        // d'un groupe ne lui retirait ni l'équipe ni la visibilité qui va avec, alors que c'est la
        // raison même de déléguer.
        teamNamed("AppSec", 5L);
        TeamMemberEntity gone = new TeamMemberEntity(9L, 10L, TeamMemberEntity.Origin.OIDC);
        alreadyIn(new TeamMemberEntity(5L, 10L, TeamMemberEntity.Origin.OIDC), gone);

        service.syncGroups(user, List.of("AppSec"));

        verify(teamMembers).delete(gone);
    }

    @Test
    @DisplayName("ce qu'un administrateur a attribué survit à la connexion")
    void neverTouchesAManualAssignment() {
        // **Le piège de l'autre côté.** Réconcilier tout aurait effacé, à chaque connexion et en
        // silence, les équipes attribuées à la main — un défaut pire que celui qu'on répare.
        teamNamed("AppSec", 5L);
        TeamMemberEntity byHand = new TeamMemberEntity(7L, 10L, TeamMemberEntity.Origin.MANUAL);
        TeamMemberEntity byScim = new TeamMemberEntity(8L, 10L, TeamMemberEntity.Origin.SCIM);
        alreadyIn(byHand, byScim);

        service.syncGroups(user, List.of("AppSec"));

        verify(teamMembers, never()).delete(byHand);
        verify(teamMembers, never()).delete(byScim);
    }

    @Test
    @DisplayName("une revendication vide ne révoque rien")
    void anEmptyClaimIsNotARevocation() {
        // Un mapper oublié, un jeton sans la revendication : l'absence de groupes est une panne de
        // configuration, pas « cette personne n'est plus dans aucune équipe ». Révoquer là-dessus
        // couperait tout le monde au premier réglage manqué.
        alreadyIn(new TeamMemberEntity(5L, 10L, TeamMemberEntity.Origin.OIDC));

        service.syncGroups(user, List.of());
        service.syncGroups(user, null);

        verify(teamMembers, never()).delete(any(TeamMemberEntity.class));
    }

    @Test
    @DisplayName("un groupe sans équipe correspondante n'est pas une erreur")
    void anUnknownGroupIsIgnored() {
        // L'annuaire d'une organisation est plus large que ce que cet outil suit.
        when(teams.findByNameIgnoreCase("Comptabilité")).thenReturn(Optional.empty());
        alreadyIn();

        service.syncGroups(user, List.of("Comptabilité"));

        verify(teamMembers, never()).save(any(TeamMemberEntity.class));
        verify(teamMembers, never()).delete(any(TeamMemberEntity.class));
    }
}

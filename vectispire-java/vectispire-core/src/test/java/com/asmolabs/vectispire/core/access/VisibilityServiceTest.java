package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMembers;
import com.asmolabs.vectispire.core.access.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamTargets;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargets;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * How a grant on a project becomes repositories (decision 0023), without a database.
 *
 * <p>The HTTP suite shows the resolution through the routes; this pins the two things only a unit
 * can see — that direct and team project grants are resolved in <b>one</b> query, and that no
 * query is issued at all when there is no project grant, since {@code project_id in ()} matches
 * every filed repository on some engines.
 */
@DisplayName("resolving a project grant")
class VisibilityServiceTest {

    private static final long USER = 7L;
    private static final long TEAM = 3L;

    private final SettingsService settings = mock(SettingsService.class);
    private final UserTargets assignments = mock(UserTargets.class);
    private final TeamMembers memberships = mock(TeamMembers.class);
    private final TeamTargets teamTargets = mock(TeamTargets.class);
    private final GrantableTargets repositories = mock(GrantableTargets.class);

    private final VisibilityService service =
            new VisibilityService(settings, assignments, memberships, teamTargets, repositories);

    @BeforeEach
    void restricted() {
        when(settings.get(Setting.TARGET_VISIBILITY)).thenReturn(VisibilityMode.ASSIGNED.wireName());
    }

    @Test
    @DisplayName("a project granted directly and one granted through a team resolve in one query, unioned")
    void projectGrantsResolveToTheirRepositories() {
        when(assignments.findByUserId(USER)).thenReturn(List.of(
                new UserTargetEntity(USER, "project", 10L),
                new UserTargetEntity(USER, "repository", 1L)));
        when(memberships.findByUserId(USER)).thenReturn(List.of(new TeamMemberEntity(TEAM, USER)));
        when(teamTargets.findByTeamIdIn(List.of(TEAM)))
                .thenReturn(List.of(new TeamTargetEntity(TEAM, "project", 20L)));
        when(repositories.repositoriesIn(anyCollection())).thenReturn(List.of(100L, 200L));

        Visibility visibility = service.of(UserView.of(reader()));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<Long>> asked = ArgumentCaptor.forClass(Collection.class);
        verify(repositories).repositoriesIn(asked.capture());
        assertThat(asked.getValue()).containsExactlyInAnyOrder(10L, 20L);

        assertThat(visibility.asFilter()).contains(Set.of(
                new ScanTarget.Repository(1L),
                new ScanTarget.Repository(100L),
                new ScanTarget.Repository(200L)));
    }

    @Test
    @DisplayName("no project grant, no project query — and still only what was granted")
    void noProjectGrantAsksNothing() {
        when(assignments.findByUserId(USER)).thenReturn(List.of(new UserTargetEntity(USER, "repository", 1L)));
        when(memberships.findByUserId(USER)).thenReturn(List.of());
        // Were the guard gone, this is what an unguarded `in ()` would answer on the engines where
        // it matches everything: every repository filed anywhere.
        when(repositories.repositoriesIn(anyCollection())).thenReturn(List.of(100L, 200L, 300L));

        Visibility visibility = service.of(UserView.of(reader()));

        verify(repositories, never()).repositoriesIn(any());
        assertThat(visibility.asFilter()).contains(Set.of(new ScanTarget.Repository(1L)));
    }

    @Test
    @DisplayName("a project holding no repository grants nothing yet, and says which project was granted")
    void anEmptyProjectGrantsNothingButIsKnown() {
        when(assignments.findByUserId(USER)).thenReturn(List.of(new UserTargetEntity(USER, "project", 10L)));
        when(memberships.findByUserId(USER)).thenReturn(List.of());
        when(repositories.repositoriesIn(anyCollection())).thenReturn(List.of());

        VisibilityService.Allowance allowance = service.allowance(UserView.of(reader()), Visibility.everything());

        assertThat(allowance.visibility().isEmpty()).isTrue();
        assertThat(allowance.grantedProjects()).containsExactly(10L);
    }

    @Test
    @DisplayName("a credential's restriction narrows a project grant, and reveals no project through it")
    void aRestrictedCredentialStaysNarrow() {
        when(assignments.findByUserId(USER)).thenReturn(List.of(new UserTargetEntity(USER, "project", 10L)));
        when(memberships.findByUserId(USER)).thenReturn(List.of());
        when(repositories.repositoriesIn(anyCollection())).thenReturn(List.of(100L, 200L));

        VisibilityService.Allowance allowance =
                service.allowance(UserView.of(reader()), Visibility.only(List.of(new ScanTarget.Repository(100L))));

        assertThat(allowance.visibility().asFilter()).contains(Set.of(new ScanTarget.Repository(100L)));
        assertThat(allowance.grantedProjects()).isEmpty();
    }

    private static UserEntity reader() {
        UserEntity user = new UserEntity();
        user.setId(USER);
        user.setUsername("reader");
        user.setRole(Role.USER.name());
        return user;
    }
}

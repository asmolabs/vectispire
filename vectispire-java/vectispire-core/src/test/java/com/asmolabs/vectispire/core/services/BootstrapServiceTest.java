package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("creating the very first account")
class BootstrapServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T08:00:00Z");
    private static final String STRONG_PASSWORD = "correct horse battery staple";

    private Users users;
    private FirstInstallDefaults firstInstallDefaults;

    @BeforeEach
    void wire() {
        users = mock(Users.class);
        firstInstallDefaults = mock(FirstInstallDefaults.class);
        when(users.save(any())).thenAnswer(call -> call.getArgument(0));
    }

    @Test
    @DisplayName("a SUPERUSER is created, and must change its password at first login")
    void createsTheFirstSuperuser() {
        when(users.count()).thenReturn(0L);

        Optional<UserEntity> created = service("admin", STRONG_PASSWORD).createFirstUser();

        assertThat(created).get().satisfies(user -> {
            assertThat(user.getUsername()).isEqualTo("admin");
            assertThat(user.getRole()).isEqualTo(Role.SUPERUSER.name());
            assertThat(user.getIsActive()).isTrue();
            assertThat(PasswordHasher.verify(STRONG_PASSWORD, user.getPassword())).isTrue();
            // The password arrived through configuration — an environment file, an
            // orchestrator's logs, a shell history. It must not stay a SUPERUSER's secret.
            assertThat(user.getMustChangePassword()).isTrue();
        });
    }

    @Test
    @DisplayName("an existing account makes the settings a no-op, not a second door")
    void doesNothingWhenAnAccountExists() {
        when(users.count()).thenReturn(1L);

        assertThat(service("admin", STRONG_PASSWORD).createFirstUser()).isEmpty();
        // Without this condition, the variables would be a permanent back door, re-armable by
        // restarting the process with the right one set.
        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("a weak password creates nothing rather than creating a weak SUPERUSER")
    void refusesAWeakPassword() {
        when(users.count()).thenReturn(0L);

        assertThat(service("admin", "short").createFirstUser()).isEmpty();
        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("missing credentials warn rather than fail: a deployment may create its account otherwise")
    void unsetCredentialsAreNotFatal() {
        when(users.count()).thenReturn(0L);

        assertThat(service(null, null).createFirstUser()).isEmpty();
    }

    @Test
    void refusesAnUnusableUsername() {
        when(users.count()).thenReturn(0L);

        assertThat(service("a", STRONG_PASSWORD).createFirstUser()).isEmpty();
    }

    @Test
    @DisplayName("an empty users table applies the safe defaults, because that is where 'new install' is known")
    void appliesTheFirstInstallDefaults() {
        when(users.count()).thenReturn(0L);

        service("admin", STRONG_PASSWORD).createFirstUser();

        // Asserted at this level and not inside FirstInstallDefaults, because no test of that
        // class can see that nothing calls it. That is the defect shape `expireStale` already
        // had: a service with passing tests and no caller.
        verify(firstInstallDefaults).apply();
    }

    @Test
    @DisplayName("credentials that are missing or refused still leave a fresh install partitioned")
    void appliesTheDefaultsEvenWhenNoAccountIsCreated() {
        when(users.count()).thenReturn(0L);

        // The install that most needs the safe value: it will be configured by hand later, by
        // somebody who never saw a release note about visibility.
        assertThat(service(null, null).createFirstUser()).isEmpty();
        assertThat(service("admin", "short").createFirstUser()).isEmpty();

        verify(firstInstallDefaults, times(2)).apply();
    }

    @Test
    @DisplayName("an existing deployment is not re-defaulted on restart")
    void leavesAnExistingDeploymentAlone() {
        when(users.count()).thenReturn(1L);

        service("admin", STRONG_PASSWORD).createFirstUser();

        // Switching an upgraded deployment to `assigned` would blank every non-administrator's
        // screens, and nobody would connect the empty backlog to a release note.
        verify(firstInstallDefaults, never()).apply();
    }

    private BootstrapService service(String username, String password) {
        return new BootstrapService(
                users,
                new BootstrapProperties(Optional.ofNullable(username), Optional.ofNullable(password)),
                firstInstallDefaults,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }
}

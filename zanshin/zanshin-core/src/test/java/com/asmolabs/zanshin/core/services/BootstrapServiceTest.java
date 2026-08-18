package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.Users;
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

    @BeforeEach
    void wire() {
        users = mock(Users.class);
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

    private BootstrapService service(String username, String password) {
        return new BootstrapService(
                users,
                new BootstrapProperties(Optional.ofNullable(username), Optional.ofNullable(password)),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }
}

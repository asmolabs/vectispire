package com.asmolabs.vectispire.core.access.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.maintenance.OneShotJobs;
import com.asmolabs.vectispire.core.settings.FirstInstallDefaults;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

@DisplayName("creating the very first account")
class BootstrapServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T08:00:00Z");
    private static final String STRONG_PASSWORD = "correct horse battery staple";

    private UserRepository users;
    private FirstInstallDefaults firstInstallDefaults;
    private OneShotJobs once;
    private RecordingTransactions transactions;

    @BeforeEach
    void wire() {
        users = mock(UserRepository.class);
        firstInstallDefaults = mock(FirstInstallDefaults.class);
        once = mock(OneShotJobs.class);
        transactions = new RecordingTransactions();
        when(users.save(any())).thenAnswer(call -> {
            transactions.events.add("save");
            return call.getArgument(0);
        });
    }

    @Test
    @DisplayName("at start, the count, the defaults, the claim and the account are one transaction")
    void startsInOneTransaction() {
        when(users.count()).thenAnswer(call -> {
            transactions.events.add("count");
            return 0L;
        });
        doAnswer(call -> transactions.events.add("defaults")).when(firstInstallDefaults).apply();
        doAnswer(call -> transactions.events.add("claim")).when(once).claim(BootstrapService.JOB);

        // Through the listener, the way the application calls it: the `@Transactional` this method had
        // was on a call from its own class, which the proxy never sees.
        service("admin", STRONG_PASSWORD).onApplicationReady();

        assertThat(transactions.events).containsExactly("begin", "count", "defaults", "claim", "save", "commit");
    }

    @Test
    @DisplayName("an install started without credentials claims nothing, so a restart with them still creates")
    void noCredentialsClaimNothing() {
        when(users.count()).thenReturn(0L);

        assertThat(service(null, null).createFirstUser()).isEmpty();

        verify(once, never()).claim(any());
    }

    @Test
    @DisplayName("a claim another instance holds rolls this one back and reads as done elsewhere")
    void aLostClaimIsAnotherInstancesAccount() {
        when(users.count()).thenReturn(0L);
        doThrow(new DataIntegrityViolationException("duplicate")).when(once).claim(BootstrapService.JOB);
        when(once.hasRun(BootstrapService.JOB)).thenReturn(true);

        assertThat(service("admin", STRONG_PASSWORD).createFirstUser()).isEmpty();

        verify(users, never()).save(any());
        assertThat(transactions.events).containsExactly("begin", "rollback");
    }

    @Test
    @DisplayName("a claim that failed with no committed row is a failure, not somebody else's account")
    void aFailedClaimIsNotALostOne() {
        when(users.count()).thenReturn(0L);
        doThrow(new QueryTimeoutException("lock wait")).when(once).claim(BootstrapService.JOB);
        when(once.hasRun(BootstrapService.JOB)).thenReturn(false);

        assertThatThrownBy(() -> service("admin", STRONG_PASSWORD).createFirstUser())
                .isInstanceOf(QueryTimeoutException.class);
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
                once,
                transactions,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    /** A transaction manager that writes down when it begins, commits and rolls back. */
    private static final class RecordingTransactions implements PlatformTransactionManager {

        final List<String> events = new ArrayList<>();

        @Override
        public TransactionStatus getTransaction(TransactionDefinition definition) {
            events.add("begin");
            return new SimpleTransactionStatus(true);
        }

        @Override
        public void commit(TransactionStatus status) {
            events.add("commit");
        }

        @Override
        public void rollback(TransactionStatus status) {
            events.add("rollback");
        }
    }
}

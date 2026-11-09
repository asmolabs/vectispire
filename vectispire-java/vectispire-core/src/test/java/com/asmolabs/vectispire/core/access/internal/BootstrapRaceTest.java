package com.asmolabs.vectispire.core.access.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.maintenance.OneShotJobs;
import com.asmolabs.vectispire.core.settings.FirstInstallDefaults;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Two instances starting together on an empty users table, on the suite's MySQL.
 *
 * <p><b>The interleaving is forced, not hoped for.</b> The first instance creates its account inside a
 * transaction this test keeps open; the second is let go and counts the table while that transaction is
 * still uncommitted — the moment both instances used to read "no account" — and only then is the first
 * one committed. Without the claim, the second went on to insert an account of its own: refused by the
 * username's key when both were configured alike (and the start failed), a second SUPERUSER when they
 * were not — the case this test configures.
 */
@DisplayName("the first account, with two instances starting at once")
class BootstrapRaceTest extends VectispireContextTest {

    private static final String STRONG_PASSWORD = "correct horse battery staple";

    @Autowired
    private UserRepository users;

    @Autowired
    private FirstInstallDefaults firstInstallDefaults;

    @Autowired
    private OneShotJobs once;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("one account is created, and the other instance reads it as created elsewhere")
    void oneAccount() throws Exception {
        CountDownLatch firstCreated = new CountDownLatch(1);
        CountDownLatch secondCounted = new CountDownLatch(1);

        BootstrapService first = service("first-admin", users);
        BootstrapService second = service("second-admin", countingThen(secondCounted));

        // Two threads of its own: the common pool may have one, and the first would then wait for ever
        // on a second that cannot start.
        try (ExecutorService instances = Executors.newFixedThreadPool(2)) {
            CompletableFuture<Optional<UserEntity>> firstOutcome = CompletableFuture.supplyAsync(
                    () -> new TransactionTemplate(transactionManager).execute(status -> {
                        Optional<UserEntity> created = first.createFirstUser();
                        firstCreated.countDown();
                        await(secondCounted);
                        return created;
                    }),
                    instances);
            assertThat(firstCreated.await(30, TimeUnit.SECONDS)).isTrue();
            CompletableFuture<Optional<UserEntity>> secondOutcome =
                    CompletableFuture.supplyAsync(second::createFirstUser, instances);

            assertThat(firstOutcome.get(60, TimeUnit.SECONDS)).get().extracting(UserEntity::getUsername)
                    .isEqualTo("first-admin");
            assertThat(secondOutcome.get(60, TimeUnit.SECONDS)).isEmpty();
        }
        assertThat(users.findAll()).extracting(UserEntity::getUsername).containsExactly("first-admin");
        assertThat(once.hasRun(BootstrapService.JOB)).isTrue();
    }

    private BootstrapService service(String username, UserRepository repository) {
        return new BootstrapService(
                repository,
                new BootstrapProperties(Optional.of(username), Optional.of(STRONG_PASSWORD)),
                firstInstallDefaults,
                once,
                transactionManager,
                clock);
    }

    /** The real repository, which says when the table has been counted. */
    private UserRepository countingThen(CountDownLatch counted) {
        return (UserRepository) Proxy.newProxyInstance(
                UserRepository.class.getClassLoader(), new Class<?>[] {UserRepository.class}, (proxy, method, args) -> {
                    try {
                        Object answer = method.invoke(users, args);
                        if (method.getName().equals("count")) {
                            counted.countDown();
                        }
                        return answer;
                    } catch (InvocationTargetException thrown) {
                        throw thrown.getCause();
                    }
                });
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                throw new IllegalStateException("The second instance never counted the users table.");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}

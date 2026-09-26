package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The sign-in ceiling under a burst, on a real engine.
 *
 * <p>The ceiling holds because each attempt commits its failure before it counts, and whether a
 * committed row is visible to a count that starts afterwards is the engine's isolation — MySQL's
 * default is repeatable read, PostgreSQL's read committed. The unit suite shows it on SQLite, whose
 * single writer serialises everything; this is the proof on the engines deployments run.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the sign-in ceiling under a burst, on a real engine")
class AuthenticationCeilingIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();
    private static final int BURST = 16;

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private AuthService auth;

    @Autowired
    private UserRepository users;

    @Test
    @DisplayName("a burst of wrong passwords reaches the verification at most five times")
    void aBurstMeetsTheCeiling() throws Exception {
        UserEntity user = new UserEntity();
        user.setUsername("burst-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash("correct horse battery staple"));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        String name = users.save(user).getUsername();

        ExecutorService pool = Executors.newFixedThreadPool(BURST);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<AuthService.Outcome>> futures = new ArrayList<>();
            for (int index = 0; index < BURST; index++) {
                String address = "198.51.100." + index;
                futures.add(pool.submit(() -> {
                    start.await();
                    return auth.login(new AuthService.LoginRequest(name, "wrong", "probe", address)).outcome();
                }));
            }
            start.countDown();
            List<AuthService.Outcome> outcomes = new ArrayList<>();
            for (Future<AuthService.Outcome> future : futures) {
                outcomes.add(future.get(120, TimeUnit.SECONDS));
            }

            assertThat(outcomes).filteredOn(AuthService.Outcome.Invalid.class::isInstance)
                    .hasSizeLessThanOrEqualTo(LoginThrottle.MAX_ATTEMPTS_PER_USER);
            assertThat(outcomes).allMatch(outcome -> outcome instanceof AuthService.Outcome.Invalid
                    || outcome instanceof AuthService.Outcome.Blocked);
        } finally {
            pool.shutdownNow();
        }
    }
}

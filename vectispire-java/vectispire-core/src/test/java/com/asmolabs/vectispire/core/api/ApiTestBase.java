package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.Users;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * The harness for the API suite: the real application, the real routes, a real database.
 *
 * <p><b>Through {@link MockMvc} and not by calling controllers.</b> The NestJS suite this
 * replaces instantiated a controller and called its methods, which proves the method works and
 * nothing about the thing the frontend actually depends on — the route's path, its status code,
 * the names of the fields in its payload, and whether the authorization rule is wired to it at
 * all. Every one of those is exactly what a port gets wrong, and none of them is visible from a
 * direct call.
 *
 * <p><b>SQLite, in the plain unit suite.</b> It needs no daemon, so these run on every {@code
 * ./gradlew build} rather than in a campaign somebody remembers to launch. The engines'
 * disagreements are the database campaign's business; what is under test here is the HTTP
 * surface, which is the same on all four.
 *
 * <p>The context and the between-test cleanup come from {@link VectispireContextTest}; what this
 * adds is the HTTP half — the filter chain, and accounts to authenticate as.
 */
abstract class ApiTestBase extends VectispireContextTest {

    /**
     * Built by hand rather than through {@code @AutoConfigureMockMvc}.
     *
     * <p>Spring Boot 4 does not put that annotation on {@code spring-boot-starter-test}'s
     * classpath, and more to the point: assembling it here makes the security filter chain an
     * <b>explicit</b> part of the harness. The default assembly is easy to get subtly wrong —
     * one forgotten filter and every authorization test passes for the wrong reason, which is
     * the failure mode a security suite must not have.
     */
    protected MockMvc mvc;

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private FilterChainProxy securityFilterChain;

    @Autowired
    protected ObjectMapper json;

    @Autowired
    private Users users;

    @Autowired
    private UserSessions sessions;

    @Autowired
    private Clock clock;

    private String adminToken;
    private String readerToken;

    /**
     * The rate limiter counts per client address, and MockMvc hands every test the same one.
     *
     * <p>It is part of the chain under test — removing it would be testing a chain nobody
     * deploys — so it is emptied between tests instead. Without that, the suite's tenth sign-in
     * exhausts the bucket and whichever test runs eleventh fails on a 429 that has nothing to do
     * with what it asserts. The order tests run in is not stable, so neither is the failure:
     * this is the shape of flakiness that gets a suite ignored rather than fixed.
     */
    @Autowired
    private com.asmolabs.vectispire.core.api.security.LoginRateLimitFilter rateLimit;

    @BeforeEach
    void buildMockMvc() {
        mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(securityFilterChain).build();
        rateLimit.reset();
        adminToken = null;
        readerToken = null;
    }

    /** A live session for an administrator, minted lazily so a test that needs none pays nothing. */
    protected String asAdmin() {
        if (adminToken == null) {
            adminToken = tokenFor("admin-" + System.nanoTime(), Role.ADMIN, false);
        }
        return adminToken;
    }

    /** A live session for an ordinary account, for the routes that must refuse one. */
    protected String asReader() {
        if (readerToken == null) {
            readerToken = tokenFor("reader-" + System.nanoTime(), Role.USER, false);
        }
        return readerToken;
    }

    /** A live session for a CISO / Security Lead account. */
    protected String asCiso() {
        return tokenFor("ciso-" + System.nanoTime(), Role.CISO, false);
    }

    /** A live session for a Security Champion account. */
    protected String asSecurityChampion() {
        return tokenFor("champion-" + System.nanoTime(), Role.SECURITY_CHAMPION, false);
    }

    /** An account that still has to change its password — the state most routes must refuse. */
    protected String asPendingPasswordChange() {
        return tokenFor("pending-" + System.nanoTime(), Role.ADMIN, true);
    }

    protected String tokenFor(String username, Role role, boolean mustChangePassword) {
        Instant now = clock.instant();

        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPassword(PasswordHasher.hash("correct horse battery staple"));
        user.setRole(role.name());
        user.setIsActive(true);
        user.setMustChangePassword(mustChangePassword);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        UserEntity saved = users.save(user);

        // Minted exactly the way the application mints one — the hash in the row, the token
        // returned to the caller. A test that stored the token would pass while the production
        // path stored a hash, and would be testing a store that no longer exists.
        Sessions.IssuedToken minted = Sessions.issue();
        SessionEntity session = new SessionEntity();
        session.setTokenHash(minted.hash());
        session.setUserId(saved.getId());
        session.setCreatedAt(now);
        session.setLastSeenAt(now);
        session.setExpiresAt(now.plus(Sessions.Policy.DEFAULT.absoluteLifetime()));
        sessions.save(session);

        return minted.token();
    }

    protected MockHttpServletRequestBuilder authenticated(MockHttpServletRequestBuilder request, String token) {
        return request.header("Authorization", "Bearer " + token);
    }

    protected String write(Object body) {
        try {
            return json.writeValueAsString(body);
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}

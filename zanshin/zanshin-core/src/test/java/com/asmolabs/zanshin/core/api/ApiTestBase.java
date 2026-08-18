package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.auth.Sessions;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.ZanshinApplication;
import com.asmolabs.zanshin.core.persistence.SessionEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.UserSessions;
import com.asmolabs.zanshin.core.repositories.Users;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
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
 * <p><b>The tables are emptied between tests, not wrapped in a rolled-back transaction.</b> The
 * usual {@code @Transactional} test would join its transaction to the request's, which changes
 * the very thing several of these routes depend on: the outbox enqueues with {@code MANDATORY},
 * the audit log writes with {@code REQUIRES_NEW}, and the scan queue deliberately runs outside
 * any transaction at all. A suite that rewrote those boundaries would be green about behaviour
 * production does not have.
 */
@SpringBootTest(classes = ZanshinApplication.class)
@ActiveProfiles("apitest")
abstract class ApiTestBase {

    /**
     * A database file nobody has touched, one per JVM.
     *
     * <p>Not {@code drop-first}, which is the obvious way and does not work: Liquibase's
     * {@code dropAll} issues a {@code DROP FOREIGN KEY} that SQLite has no generator for, so the
     * context fails to start with a message about statement generators rather than about the
     * schema. Not {@code :memory:} either — Liquibase and Hibernate open separate connections,
     * and each would get its own empty database.
     */
    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        Path file = Path.of(System.getProperty("java.io.tmpdir"), "zanshin-apitest-" + UUID.randomUUID() + ".db");
        file.toFile().deleteOnExit();
        registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + file);
    }

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

    @Autowired
    private JdbcTemplate jdbc;

    private String adminToken;
    private String readerToken;

    /**
     * Every table, children before parents.
     *
     * <p>Listed rather than discovered: a generated order would be right until the day a new
     * foreign key changes it, and the failure — a delete refused mid-cleanup — reads as a broken
     * test rather than as a missing entry here.
     */
    private static final List<String> TABLES_CHILDREN_FIRST = List.of(
            "t_ai_review_result",
            "t_finding",
            "t_issue",
            "t_scan",
            "t_gate_policy",
            "t_processed_message",
            "t_outbox_message",
            "t_audit_log",
            "t_login_attempt",
            "t_session",
            "t_api_key",
            "t_agent",
            "t_repository",
            "t_container",
            "t_ssh_key",
            "t_semgrep_rule_set",
            "t_leader_lease",
            "t_setting",
            "t_user");

    @BeforeEach
    void buildMockMvcAndEmptyTheDatabase() {
        mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(securityFilterChain).build();
        adminToken = null;
        readerToken = null;
        TABLES_CHILDREN_FIRST.forEach(table -> jdbc.execute("delete from " + table));
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

        SessionEntity session = new SessionEntity();
        session.setToken(Sessions.newToken());
        session.setUserId(saved.getId());
        session.setCreatedAt(now);
        session.setLastSeenAt(now);
        session.setExpiresAt(now.plus(Sessions.Policy.DEFAULT.absoluteLifetime()));
        sessions.save(session);

        return session.getToken();
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

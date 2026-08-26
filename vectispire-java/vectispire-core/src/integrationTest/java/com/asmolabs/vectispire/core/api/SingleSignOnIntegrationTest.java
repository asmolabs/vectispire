package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import java.io.IOException;
import java.net.CookieManager;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

/**
 * The whole sign-on, against a real Keycloak.
 *
 * <h2>Why this needs a server and not a stub</h2>
 *
 * <p>Everything the unit tests cover happens <em>after</em> an identity is known. What they
 * cannot see is the part that actually breaks: whether discovery reads a real
 * {@code .well-known} document, whether the authorization redirect is built with the right
 * client and scopes, whether the code exchange succeeds against a real token endpoint, whether
 * the issuer in the returned identity matches the one configured, and whether the hand-off
 * cookie survives the round trip. A simulated provider answers all of those the way the
 * simulation was written, which proves the simulation.
 *
 * <p>So the flow is driven end to end with an HTTP client: the redirect out, Keycloak's own login
 * form, the redirect back with a code, the hand-off cookie, the exchange, and finally a call to
 * an authenticated route with the session that came out. Nothing is mocked.
 *
 * <h2>Pinned by digest</h2>
 *
 * <p>Like the scanner images, and for a weaker but real version of the same reason: a test whose
 * subject changes under it reports on something nobody chose. {@code latest} moving is how a
 * suite starts failing for a reason unrelated to the commit that failed it.
 */
@SpringBootTest(classes = VectispireApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("signing in through an identity provider")
class SingleSignOnIntegrationTest {

    private static final DockerImageName KEYCLOAK = DockerImageName.parse(
            "quay.io/keycloak/keycloak@sha256:5fdbf2dbb5897cc34e82de49d13e23db011f9925089dbc555fc095f2c8bc1dac");

    private static final String REALM = "vectispire";
    private static final String CLIENT_ID = "vectispire-ui";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String PERSON = "alice";
    private static final String PASSWORD = "correct horse battery staple";

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> DATABASE = ENGINE.container();

    @SuppressWarnings("resource")
    private static final GenericContainer<?> KEYCLOAK_SERVER = new GenericContainer<>(KEYCLOAK)
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyToContainer(Transferable.of(realmDefinition()), "/opt/keycloak/data/import/realm.json")
            .withCommand("start-dev", "--import-realm")
            // The discovery document, not the home page: the application's first act is to read
            // it, and a container that answers HTML while still building its realm would make
            // the context fail to start for a reason that looks like a bad issuer.
            .waitingFor(Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                    .forPort(8080)
                    .withStartupTimeout(Duration.ofMinutes(3)));

    @BeforeAll
    static void start() {
        DATABASE.ifPresent(JdbcDatabaseContainer::start);
        KEYCLOAK_SERVER.start();
    }

    @AfterAll
    static void stop() {
        KEYCLOAK_SERVER.stop();
        DATABASE.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, DATABASE, registry);
        // The issuer the application discovers from, and the one Keycloak will put in the token
        // it issues — the same string, or the identity would be rejected as coming from
        // somewhere else.
        registry.add("vectispire.oidc.issuer", () -> issuer());
        registry.add("vectispire.oidc.client-id", () -> CLIENT_ID);
        registry.add("vectispire.oidc.client-secret", () -> CLIENT_SECRET);
    }

    /**
     * <b>A literal IPv4 address, and both halves of that are load-bearing.</b>
     *
     * <p><i>An address rather than a name</i>, because of a JDK trap:
     * {@link java.net.HttpCookie#domainMatches} refuses any domain with no embedded dot, so a
     * cookie set for {@code localhost} is stored by {@link CookieManager} and never sent back.
     * Keycloak's authentication session lives in such a cookie: the login form posts without it,
     * Keycloak re-renders the form, and the flow appears to fail on bad credentials that are
     * perfectly good. The same request through curl succeeds, which is how this was found.
     *
     * <p><i>Resolved rather than hard-coded</i>, because {@code 127.0.0.1} is only the right
     * answer when the daemon shares this process's network namespace. On CI it does not: the
     * container is published on the {@code docker:dind} service, and the first nightly run
     * failed with {@code Connection refused} against {@code http://127.0.0.1:32769}. Testcontainers
     * knows the right host — {@code docker} there, via {@code TESTCONTAINERS_HOST_OVERRIDE} — and
     * resolving it yields an address that is both reachable and dotted. Using that name directly
     * would satisfy the second constraint and break the first: {@code domainMatches("docker")} is
     * false, exactly like {@code localhost}.
     *
     * <p>Keycloak derives the issuer of the tokens it signs from the host it was called on, so
     * the address used here has to be the one configured — hence one accessor for both.
     */
    private static String host() {
        String reported = KEYCLOAK_SERVER.getHost();
        try {
            for (InetAddress address : InetAddress.getAllByName(reported)) {
                // IPv4 specifically: `::1` has no dot either, and would reopen the cookie trap.
                if (address instanceof Inet4Address) {
                    return address.getHostAddress();
                }
            }
        } catch (UnknownHostException resolutionFailed) {
            // Nothing useful to do here: the name Testcontainers reported is the best guess left,
            // and the connection error that follows says more than a swallowed exception would.
        }
        return reported;
    }

    private static String issuer() {
        return "http://" + host() + ":" + KEYCLOAK_SERVER.getMappedPort(8080) + "/realms/" + REALM;
    }

    @LocalServerPort
    private int port;

    @Autowired
    private Users users;

    @BeforeEach
    void anAdministratorHasPreparedTheAccount() {
        jar.clear();
        users.deleteAll();
        UserEntity alice = new UserEntity();
        alice.setUsername(PERSON);
        alice.setDisplayName("Alice");
        alice.setRole(Role.USER.name());
        alice.setIsActive(true);
        alice.setMustChangePassword(false);
        alice.setCreatedAt(Instant.now());
        alice.setUpdatedAt(Instant.now());
        users.save(alice);
    }

    @Test
    @DisplayName("the discovery document is read, and the button offered")
    void theProviderIsDiscovered() throws Exception {
        // Proves the bean was built from a real `.well-known` document at startup — the context
        // would not have come up otherwise, and this is what says so out loud.
        HttpResponse<String> methods = plainClient().send(
                HttpRequest.newBuilder(URI.create(app("/api/v1/auth/methods"))).build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(methods.statusCode()).isEqualTo(200);
        assertThat(methods.body()).contains("\"configured\":true");
    }

    @Test
    @DisplayName("a prepared account signs in, and comes back with a Vectispire session")
    void theWholeFlow() throws Exception {
        // 1. The application hands the browser to the provider.
        HttpResponse<String> toProvider = browse(HttpRequest.newBuilder(URI.create(app("/oauth2/authorization/oidc"))));

        // The client and the scopes are built here, and a wrong one fails at the provider rather
        // than in Vectispire — which is why asserting on the redirect is worth a line.
        assertThat(toProvider.uri().toString()).contains("/realms/" + REALM + "/protocol/openid-connect/auth");
        assertThat(toProvider.uri().toString()).contains("client_id=" + CLIENT_ID);
        assertThat(toProvider.uri().toString()).contains("scope=openid");

        // 2. Keycloak's own login form, filled in.
        HttpResponse<String> afterLogin = browse(HttpRequest.newBuilder(URI.create(formActionOf(toProvider.body())))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "username=" + PERSON + "&password=" + encode(PASSWORD) + "&credentialId=")));

        // 3. Back at Vectispire, which exchanged the code server-side and minted a session.
        assertThat(afterLogin.uri().toString())
                .describedAs("the sign-on ends on the screen that completes it")
                .contains("/login?sso=complete");

        assertThat(jar).containsKey("zs_handoff");

        // 4. The one-time cookie is traded for the session token.
        HttpResponse<String> exchanged = browse(HttpRequest.newBuilder(URI.create(app("/api/v1/auth/session/exchange")))
                .POST(HttpRequest.BodyPublishers.noBody()));

        assertThat(exchanged.statusCode()).isEqualTo(200);
        assertThat(exchanged.body()).contains("\"username\":\"" + PERSON + "\"");

        // 5. And the session works on an ordinary route, which is the only proof that matters.
        String token = between(exchanged.body(), "\"token\":\"", "\"");
        HttpResponse<String> me = plainClient().send(
                HttpRequest.newBuilder(URI.create(app("/api/v1/auth/me")))
                        .header("Authorization", "Bearer " + token)
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(me.statusCode()).isEqualTo(200);
        assertThat(me.body()).contains(PERSON);
    }

    @Test
    @DisplayName("an identity with no Vectispire account is refused, and says so")
    void anUnpreparedIdentityIsRefused() throws Exception {
        // The decision this feature was built around: single sign-on says who somebody is, not
        // that they may come in. Alice exists in the realm and, here, not in Vectispire.
        users.deleteAll();

        HttpResponse<String> toProvider = browse(HttpRequest.newBuilder(URI.create(app("/oauth2/authorization/oidc"))));
        HttpResponse<String> afterLogin = browse(HttpRequest.newBuilder(URI.create(formActionOf(toProvider.body())))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "username=" + PERSON + "&password=" + encode(PASSWORD) + "&credentialId=")));

        assertThat(afterLogin.uri().toString()).contains("sso=refused");
        assertThat(java.net.URLDecoder.decode(afterLogin.uri().toString(), StandardCharsets.UTF_8))
                .contains("An administrator has to create it first");
        assertThat(jar).doesNotContainKey("zs_handoff");
    }

    private String app(String path) {
        return "http://" + host() + ":" + port + path;
    }

    /**
     * A browser's cookie jar, kept by hand.
     *
     * <p><b>{@link CookieManager} was the obvious choice and does not work here.</b> It stores
     * Keycloak's authentication cookie and never sends it back — {@code HttpCookie.domainMatches}
     * refuses a bare host — and the flow then fails as
     * {@code error="cookie_not_found"} in Keycloak's log, which reads exactly like bad
     * credentials. The same requests through curl succeed, which is how this was found.
     *
     * <p>Fifteen lines of explicit jar remove a whole class of JDK quirk from a test whose
     * subject is a protocol, and make what the browser sends readable in the test.
     */
    private final Map<String, String> jar = new LinkedHashMap<>();

    /** Sends, records what was set, and follows redirects the way a browser would. */
    private HttpResponse<String> browse(HttpRequest.Builder builder) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(20))
                .build();

        HttpResponse<String> response = send(client, builder);
        // Bounded: a redirect loop is a defect to see as a failure, not as a hung suite.
        for (int hop = 0; hop < 10 && isRedirect(response); hop++) {
            URI next = response.uri().resolve(response.headers().firstValue("location").orElseThrow());
            response = send(client, HttpRequest.newBuilder(next).GET());
        }
        return response;
    }

    private HttpResponse<String> send(HttpClient client, HttpRequest.Builder builder) throws Exception {
        if (!jar.isEmpty()) {
            builder.header("Cookie", jar.entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .reduce((left, right) -> left + "; " + right)
                    .orElseThrow());
        }
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        for (String header : response.headers().allValues("set-cookie")) {
            String pair = header.split(";", 2)[0];
            int equals = pair.indexOf('=');
            if (equals > 0) {
                String name = pair.substring(0, equals).trim();
                String value = pair.substring(equals + 1).trim();
                // An empty value is a deletion, which is what the exchange does to the hand-off.
                if (value.isEmpty()) {
                    jar.remove(name);
                } else {
                    jar.put(name, value);
                }
            }
        }
        return response;
    }

    private static boolean isRedirect(HttpResponse<String> response) {
        return response.statusCode() / 100 == 3 && response.headers().firstValue("location").isPresent();
    }

    private static HttpClient plainClient() {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();
    }

    /**
     * The form Keycloak asks a person to fill in.
     *
     * <p>Read out of the page rather than guessed: the action carries the session code and the
     * tab id, which change on every attempt. Brittle in principle — it is somebody else's HTML —
     * and the alternative is not testing the part where the person actually signs in.
     */
    private static String formActionOf(String html) throws IOException {
        Matcher matcher = Pattern.compile("action=\"([^\"]+)\"").matcher(html);
        if (!matcher.find()) {
            throw new IOException("Keycloak's login page carried no form action:\n" + html);
        }
        return matcher.group(1).replace("&amp;", "&");
    }

    private static String between(String body, String start, String end) {
        int from = body.indexOf(start) + start.length();
        return body.substring(from, body.indexOf(end, from));
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * The realm, imported at startup.
     *
     * <p>Written here rather than fetched or built through the admin API: a test's fixture should
     * be readable in the test. {@code redirectUris} is a wildcard because the application's port
     * is chosen at run time and the realm is created before it is known — acceptable for a realm
     * that lives for the length of one suite, and not a pattern to copy into a deployment.
     */
    private static String realmDefinition() {
        return """
                {
                  "realm": "%s",
                  "enabled": true,
                  "sslRequired": "none",
                  "clients": [
                    {
                      "clientId": "%s",
                      "enabled": true,
                      "protocol": "openid-connect",
                      "publicClient": false,
                      "secret": "%s",
                      "standardFlowEnabled": true,
                      "redirectUris": ["*"],
                      "webOrigins": ["*"]
                    }
                  ],
                  "users": [
                    {
                      "username": "%s",
                      "enabled": true,
                      "emailVerified": true,
                      "email": "alice@example.com",
                      "firstName": "Alice",
                      "lastName": "Martin",
                      "credentials": [{ "type": "password", "value": "%s", "temporary": false }]
                    }
                  ]
                }
                """.formatted(REALM, CLIENT_ID, CLIENT_SECRET, PERSON, PASSWORD);
    }
}

package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The realm the {@code sso} profile imports.
 *
 * <p><b>Two settings in it break silently, and they are the ones people get wrong when configuring
 * Keycloak by hand.</b> The file is shipped precisely to avoid that manual configuration; if it
 * carries the mistake itself, it spreads it instead of sparing it, and nothing says so — sign-in
 * succeeds, the teams stay empty, and nobody knows why.
 *
 * <p>This case does not start Keycloak: {@code SingleSignOnIntegrationTest} drives the full flow
 * against a real server, with a realm of its own using a wildcard URI because it runs on a random
 * port. This one pins the contents of the shipped file, which the other cannot do.
 */
@DisplayName("the realm shipped with the sso profile")
class ShippedRealmTest {

    /** From the module's directory, the repository root is two levels up. */
    private static final Path REALM = Path.of("../../ci/keycloak/vectispire-realm.json");

    private static JsonNode realm() throws Exception {
        assertThat(Files.exists(REALM))
                .as("the shipped realm is not at %s — a test that cannot find its subject would "
                        + "pass forever", REALM.toAbsolutePath().normalize())
                .isTrue();
        return new ObjectMapper().readTree(Files.readString(REALM));
    }

    @Test
    @DisplayName("the group mapper emits plain names, not paths")
    void theGroupMapperEmitsPlainNames() throws Exception {
        JsonNode mapper = realm().at("/clients/0/protocolMappers/0/config");

        // **Trap number one.** `ExternalIdentityService.syncGroups` matches the value received
        // against the team name. With full path switched on, Keycloak emits "/AppSec", no team is
        // called that, and the synchronisation does nothing — no error, no log, nothing to guess
        // from.
        assertThat(mapper.path("full.path").asText())
                .as("full path = no team ever matches")
                .isEqualTo("false");
        assertThat(mapper.path("claim.name").asText()).isEqualTo("groups");
        assertThat(mapper.path("id.token.claim").asText())
                .as("the claim is read from the identity token")
                .isEqualTo("true");
    }

    @Test
    @DisplayName("the redirect URI is the one Spring Security listens on")
    void theRedirectUriMatchesTheFilterChain() throws Exception {
        // **Trap number two.** The path is not a matter of choice: it is the `oauth2Login`
        // filter's. A near-miss URI gives an "invalid redirect_uri" that people spend half a day
        // blaming on the client, the secret or the issuer.
        assertThat(realm().at("/clients/0/redirectUris"))
                .allSatisfy(uri -> assertThat(uri.asText()).endsWith("/login/oauth2/code/oidc"));
    }

    @Test
    @DisplayName("the realm's account carries the name bootstrap creates by default")
    void theRealmUserMatchesTheBootstrapAccount() throws Exception {
        // No account is created at sign-in: the first binding is made on the username. If the two
        // do not coincide, nobody gets in once the password door is closed — and closing it is when
        // that gets noticed.
        assertThat(realm().at("/users/0/username").asText())
                .as("must equal the VECTISPIRE_BOOTSTRAP_USERNAME default in docker-compose.yml")
                .isEqualTo("admin");
    }

    @Test
    @DisplayName("the example configuration lets that account be linked, since it is a SUPERUSER")
    void theExampleAllowsLinkingThePrivilegedAccount() throws Exception {
        // An administrative account is not bound on a username claim unless the operator allows
        // it, and the realm's only user is the bootstrap SUPERUSER. Without the line, the `sso`
        // profile refused its own demonstration account.
        Path example = Path.of("../../.env.oidc.example");
        assertThat(Files.readAllLines(example))
                .as("%s must allow linking the evaluation realm's admin", example.toAbsolutePath().normalize())
                .contains("VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS=true");
    }
}

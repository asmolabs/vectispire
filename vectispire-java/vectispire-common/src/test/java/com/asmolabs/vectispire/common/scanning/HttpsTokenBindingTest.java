package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * An HTTPS token reaches its own host and no other (decision 0022) — measured against JGit, not
 * assumed of it.
 *
 * <p>Two local servers stand in for a forge and for wherever a redirect points: the first demands
 * authentication, then redirects; the second records what arrives. Plain HTTP, because what is under
 * test is the credential JGit decides to send, and TLS would change nothing about that decision.
 */
@DisplayName("an HTTPS token and the host it is bound to")
class HttpsTokenBindingTest {

    private HttpServer forge;
    private HttpServer elsewhere;
    private final List<String> authorizationSeenElsewhere = new CopyOnWriteArrayList<>();
    private final List<String> authorizationSeenAtForge = new CopyOnWriteArrayList<>();

    @AfterEach
    void stop() {
        if (forge != null) forge.stop(0);
        if (elsewhere != null) elsewhere.stop(0);
    }

    @Test
    @DisplayName("a redirect to another host receives no credential")
    void aRedirectGetsNothing() throws Exception {
        elsewhere = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        elsewhere.createContext("/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            authorizationSeenElsewhere.add(auth == null ? "" : auth);
            exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"elsewhere\"");
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
        });
        elsewhere.start();
        int elsewherePort = elsewhere.getAddress().getPort();

        forge = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        forge.createContext("/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null) {
                exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"forge\"");
                exchange.sendResponseHeaders(401, -1);
            } else {
                authorizationSeenAtForge.add(auth);
                exchange.getResponseHeaders().add("Location",
                        "http://127.0.0.1:" + elsewherePort + exchange.getRequestURI());
                exchange.sendResponseHeaders(301, -1);
            }
            exchange.close();
        });
        forge.start();
        int forgePort = forge.getAddress().getPort();

        GitClone.HostBoundCredentials credentials = new GitClone.HostBoundCredentials(
                new ScanTask.Target.HttpsCredential("localhost", null, "glpat-secret-token"));

        try {
            Git.lsRemoteRepository()
                    .setRemote("http://localhost:" + forgePort + "/team/repo.git")
                    .setCredentialsProvider(credentials)
                    .call();
        } catch (Exception expected) {
            // The second server refuses; what matters is what it was sent.
        }

        assertThat(authorizationSeenAtForge).as("the bound host is authenticated").isNotEmpty();
        assertThat(authorizationSeenElsewhere).as("the redirect target was reached").isNotEmpty();
        assertThat(authorizationSeenElsewhere)
                .as("no Authorization header may follow the redirect to another host")
                .allMatch(String::isEmpty);
    }

    @Test
    @DisplayName("the provider answers for its host only")
    void theProviderAnswersForItsHostOnly() throws Exception {
        GitClone.HostBoundCredentials credentials = new GitClone.HostBoundCredentials(
                new ScanTask.Target.HttpsCredential("gitlab.example.com", "ci", "glpat-secret-token"));
        org.eclipse.jgit.transport.CredentialItem.Username user = new org.eclipse.jgit.transport.CredentialItem.Username();
        org.eclipse.jgit.transport.CredentialItem.Password password = new org.eclipse.jgit.transport.CredentialItem.Password();

        assertThat(credentials.get(new org.eclipse.jgit.transport.URIish("https://evil.example.net/x.git"), user, password)).isFalse();
        assertThat(password.getValue()).isNull();
        assertThat(credentials.get(new org.eclipse.jgit.transport.URIish("https://GitLab.Example.com/x.git"), user, password)).isTrue();
        assertThat(new String(password.getValue())).isEqualTo("glpat-secret-token");
        assertThat(user.getValue()).isEqualTo("ci");
    }

    @Test
    @DisplayName("a clone whose URL names another host than the token's is refused before the network")
    void aMismatchedHostIsRefusedUpFront(@org.junit.jupiter.api.io.TempDir java.nio.file.Path into) {
        GitClone.Request request = new GitClone.Request(
                "https://evil.example.net/team/repo.git", "main", into, null, java.time.Duration.ofSeconds(5),
                new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE,
                new ScanTask.Target.HttpsCredential("gitlab.example.com", null, "glpat-secret-token"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> GitClone.clone(request))
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("sent to no other host")
                .hasMessageNotContaining("glpat-secret-token");
    }
}

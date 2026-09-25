package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.eclipse.jgit.api.Git;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A clone reaches the host its URL names, and no host a redirect names — measured against JGit.
 *
 * <p>Two local servers: the "forge" answers the first smart-HTTP request with a redirect, the way a
 * hostile or compromised repository host would point a clone at {@code 169.254.169.254}; the other
 * records whether anything arrived. The clone names {@code localhost} and the redirect
 * {@code 127.0.0.1}: two hosts as JGit sees them, both reachable on any machine without a loopback
 * alias. {@code HttpsTokenBindingTest} shows that, left to itself, JGit
 * follows that redirect — it asserts the second server was reached. Plain HTTP because
 * {@link GitClone#clone} accepts only {@code https://}, so the clone runs through the same
 * {@link GitClone#transportCallback} that method installs, not through a copy of it.
 */
@DisplayName("a clone and the redirects its forge answers with")
class CloneRedirectTest {

    private HttpServer forge;
    private HttpServer elsewhere;
    private final List<String> reachedElsewhere = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws Exception {
        elsewhere = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        elsewhere.createContext("/", exchange -> {
            reachedElsewhere.add(exchange.getRequestURI().toString());
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        elsewhere.start();
        int elsewherePort = elsewhere.getAddress().getPort();

        forge = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        forge.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://127.0.0.1:" + elsewherePort + exchange.getRequestURI());
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        forge.start();
    }

    @AfterEach
    void stop() {
        forge.stop(0);
        elsewhere.stop(0);
    }

    @Test
    @DisplayName("the redirect on the first request is refused, by name, and its target never reached")
    void theInitialRedirectIsNotFollowed(@TempDir Path into) {
        String url = "http://localhost:" + forge.getAddress().getPort() + "/team/repo.git";
        GitClone.Request request = new GitClone.Request(url, "main", into, new GitClone.HostKeyPolicy.TrustEveryHost());

        Throwable failure = catchThrowable(() -> Git.cloneRepository()
                .setURI(url)
                .setDirectory(into.resolve("clone").toFile())
                .setBranch("main")
                .setTransportConfigCallback(GitClone.transportCallback(request, List.of()))
                .call()
                .close());

        assertThat(reachedElsewhere).as("the host the redirect named was contacted").isEmpty();
        assertThat(failure)
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("answered with a redirect (302) to 127.0.0.1")
                .hasMessageContaining("follows no redirect");
    }
}

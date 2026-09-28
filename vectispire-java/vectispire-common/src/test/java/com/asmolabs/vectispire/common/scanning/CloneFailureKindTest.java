package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.asmolabs.vectispire.common.domain.scans.FailureKind;
import com.asmolabs.vectispire.common.scanning.CloneFailureException.Kind;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.errors.NoRemoteRepositoryException;
import org.eclipse.jgit.internal.JGitText;
import org.eclipse.jgit.transport.URIish;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * What a failed clone is, as a kind the scan's fate hangs on — measured against what JGit and MINA
 * actually raise, not against messages written for the test.
 *
 * <p>A local plain-HTTP forge answers each status a real one does; {@link GitClone#fetch} is called
 * directly because {@link GitClone#clone} accepts only {@code https://}, and it installs the same
 * connection wiring the clone does. The SSH kinds are measured in {@code SshCloneTest}, against a real
 * SSH server.
 */
@DisplayName("the kind of a failed clone")
class CloneFailureKindTest {

    @TempDir
    Path dir;

    private HttpServer forge;

    @AfterEach
    void stop() {
        if (forge != null) {
            forge.stop(0);
        }
    }

    private String answering(int status) throws Exception {
        forge = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        forge.createContext("/", exchange -> {
            if (status == 401) {
                exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"forge\"");
            }
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        forge.start();
        return "http://localhost:" + forge.getAddress().getPort() + "/team/repo.git";
    }

    private CloneFailureException fetching(String url) {
        GitClone.Request request = new GitClone.Request(
                url, "main", dir.resolve("clone-" + System.nanoTime()), null, Duration.ofSeconds(2),
                new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE);
        return catchThrowableOfType(CloneFailureException.class, () -> GitClone.fetch(request, List.of()));
    }

    @ParameterizedTest(name = "HTTP {0} is {1}")
    @CsvSource({
        "401, AUTHENTICATION",
        "403, AUTHENTICATION",
        "404, NOT_FOUND",
        "410, NOT_FOUND",
        "500, UNAVAILABLE",
        "503, UNAVAILABLE",
        "429, UNAVAILABLE"
    })
    @DisplayName("a forge's answer is read off its status, which JGit's own exception does not carry")
    void theStatusDecides(int status, Kind expected) throws Exception {
        CloneFailureException failure = fetching(answering(status));

        assertThat(failure).isNotNull();
        assertThat(failure.kind()).isEqualTo(expected);
    }

    @Test
    @DisplayName("an authentication refused over HTTPS is permanent, and says so")
    void anAuthenticationRefusedIsPermanent() throws Exception {
        CloneFailureException failure = fetching(answering(401));

        assertThat(failure.failureKind()).isEqualTo(FailureKind.PERMANENT);
        assertThat(failure).hasMessageContaining("requires authentication");
    }

    @Test
    @DisplayName("a refused connection is the network, transient")
    void aRefusedConnectionIsTheNetwork() throws Exception {
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }

        CloneFailureException failure = fetching("http://127.0.0.1:" + closed + "/team/repo.git");

        assertThat(failure.kind()).isEqualTo(Kind.NETWORK);
        assertThat(failure.failureKind()).isEqualTo(FailureKind.TRANSIENT);
        assertThat(failure).hasMessageContaining("could not reach its host");
    }

    @Test
    @DisplayName("a forge that accepts and never answers is a timeout, transient")
    void aSilentForgeTimesOut() throws Exception {
        try (ServerSocket silent = new ServerSocket(0)) {
            CloneFailureException failure = fetching("http://127.0.0.1:" + silent.getLocalPort() + "/team/repo.git");

            assertThat(failure.kind()).isEqualTo(Kind.TIMEOUT);
            assertThat(failure.failureKind()).isEqualTo(FailureKind.TRANSIENT);
        }
    }

    @Test
    @DisplayName("a host no resolver knows is the network, transient")
    void anUnknownHostIsTheNetwork() {
        // `.invalid` is reserved never to resolve (RFC 6761).
        CloneFailureException failure = fetching("http://forge.vectispire.invalid/team/repo.git");

        assertThat(failure.kind()).isEqualTo(Kind.NETWORK);
    }

    private static GitClone.Request request(String branch) {
        return new GitClone.Request("ssh://git@host/p.git", branch, Path.of("/tmp/unused"), "key", Duration.ofMinutes(1),
                new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE);
    }

    @Test
    @DisplayName("MINA's disconnect reasons decide a host key and an authentication, wherever JGit wraps them")
    void theSshReasonsDecide() {
        Exception hostKey = new TransportException("ssh://git@host/p.git: whatever JGit says",
                new SshException(SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "reworded"));
        Exception authentication = new TransportException("ssh://git@host/p.git: Cannot log in",
                new SshException(SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "reworded"));
        Exception other = new TransportException("ssh://git@host/p.git: broken",
                new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Server key did not validate"));

        assertThat(GitClone.diagnose(request("main"), hostKey, 0).kind()).isEqualTo(Kind.HOST_KEY);
        assertThat(GitClone.diagnose(request("main"), authentication, 0).kind()).isEqualTo(Kind.AUTHENTICATION);
        // The words of a host-key refusal with another reason choose the sentence, never the kind.
        GitClone.Diagnosis worded = GitClone.diagnose(request("main"), other, 0);
        assertThat(worded.kind()).isEqualTo(Kind.UNCLASSIFIED);
        assertThat(worded.sentence()).contains("host key");
    }

    @Test
    @DisplayName("JGit's own type for an absent repository decides it")
    void theRepositoryTypeDecides() throws Exception {
        Exception absent = new TransportException("Invalid remote: origin",
                new NoRemoteRepositoryException(new URIish("ssh://git@host/p.git"), "whatever the forge says"));

        assertThat(GitClone.diagnose(request("main"), absent, 0).kind()).isEqualTo(Kind.NOT_FOUND);
    }

    @Test
    @DisplayName("an absent branch is JGit's own sentence for that branch, and nothing near it")
    void anAbsentBranchIsJGitsSentence() {
        String jgit = MessageFormat.format(JGitText.get().remoteBranchNotFound, "release");
        String another = MessageFormat.format(JGitText.get().remoteBranchNotFound, "other");

        assertThat(GitClone.diagnose(request("release"), new TransportException(jgit), 0).kind())
                .isEqualTo(Kind.BRANCH_ABSENT);
        GitClone.Diagnosis near = GitClone.diagnose(request("release"), new TransportException(another), 0);
        assertThat(near.kind()).as("about a branch the scan did not ask for").isEqualTo(Kind.UNCLASSIFIED);
        assertThat(GitClone.diagnose(request("release"), new TransportException("Remote branch release not found"), 0)
                        .kind())
                .as("an English literal that is not JGit's sentence")
                .isEqualTo(Kind.UNCLASSIFIED);
    }

    @Test
    @DisplayName("a message that reads like a refusal but carries no type retries")
    void wordsAloneDoNotFail() {
        GitClone.Diagnosis authLike = GitClone.diagnose(request("main"), new TransportException("Auth fail"), 0);

        assertThat(authLike.kind()).isEqualTo(Kind.UNCLASSIFIED);
        assertThat(authLike.sentence()).contains("Authentication refused");
    }

    @Test
    @DisplayName("each kind has the fate the owner decided for it")
    void eachKindHasItsFate() {
        Map<Kind, FailureKind> decided = new EnumMap<>(Kind.class);
        decided.put(Kind.HOST_KEY, FailureKind.PERMANENT);
        decided.put(Kind.AUTHENTICATION, FailureKind.PERMANENT);
        decided.put(Kind.NOT_FOUND, FailureKind.PERMANENT);
        decided.put(Kind.BRANCH_ABSENT, FailureKind.PERMANENT);
        decided.put(Kind.CREDENTIAL, FailureKind.PERMANENT);
        decided.put(Kind.URL_REFUSED, FailureKind.PERMANENT);
        decided.put(Kind.SUB_PATH, FailureKind.PERMANENT);
        decided.put(Kind.TIMEOUT, FailureKind.TRANSIENT);
        decided.put(Kind.NETWORK, FailureKind.TRANSIENT);
        decided.put(Kind.UNAVAILABLE, FailureKind.TRANSIENT);
        decided.put(Kind.UNCLASSIFIED, FailureKind.TRANSIENT);

        assertThat(decided).as("a kind added without a decision").hasSize(Kind.values().length);
        decided.forEach((kind, fate) -> assertThat(kind.failureKind()).as(kind.name()).isEqualTo(fate));
    }
}

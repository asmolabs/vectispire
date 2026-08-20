package com.asmolabs.zanshin.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Duration;
import org.eclipse.jgit.api.errors.TransportException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("repository clone")
class GitCloneTest {

    private static final Path INTO = Path.of("/tmp/zanshin-clone-test");

    private static GitClone.Request request(String url, String key) {
        return new GitClone.Request(url, "main", INTO, key, Duration.ofMinutes(5), new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE);
    }

    @ParameterizedTest(name = "refuses {0} before any network call")
    @ValueSource(strings = {"file:///etc/passwd", "ext::sh -c whoami", "", "not a url"})
    void refusesUnsafeUrlsBeforeConnecting(String url) {
        // Revalidated here although it was validated on entry: rows predating that validation
        // exist, and an unchecked URL reaching a clone is arbitrary code execution — `ext::`
        // makes git itself run a command.
        assertThatThrownBy(() -> GitClone.clone(request(url, null)))
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("Repository URL refused");
    }

    @Test
    @DisplayName("an unreadable deployment key says so, rather than failing as an auth error")
    void unreadableKeyIsItsOwnMessage() {
        // "Permission denied" would send the operator to the provider's settings for a key that
        // was never parseable in the first place.
        assertThatThrownBy(() -> GitClone.clone(request("ssh://git@example.com/org/project.git", "not a key")))
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("could not be read");
    }

    @Test
    @DisplayName("names the branch when the branch is what is missing")
    void explainsAMissingBranch() {
        // Git's own message says neither which repository nor which branch. This error lands in
        // an agent's log, hours after the action that caused it.
        String explanation = GitClone.explain(
                request("ssh://git@example.com/org/project.git", null),
                new TransportException("Remote branch main not found in upstream origin"));

        assertThat(explanation).contains("main").contains("does not exist");
    }

    @Test
    @DisplayName("tells an operator with a key apart from one without")
    void explainsAuthenticationDifferently() {
        // With a key attached, the useful question is whether the provider knows it. Without
        // one, the useful action is to attach one.
        assertThat(GitClone.explain(request("ssh://git@host/p.git", "key"), new TransportException("Auth fail")))
                .contains("declared with the provider");
        assertThat(GitClone.explain(request("ssh://git@host/p.git", null), new TransportException("Auth fail")))
                .contains("Attach an SSH key");
    }

    @Test
    @DisplayName("reads the cause chain, not just the outermost message")
    void looksThroughTheCauseChain() {
        // JGit wraps the transport's own failure, and the sentence that identifies it is
        // usually two levels down.
        Exception wrapped = new TransportException("clone failed", new IllegalStateException("Auth fail"));

        assertThat(GitClone.explain(request("ssh://git@host/p.git", "key"), wrapped))
                .contains("Authentication refused");
    }

    @Test
    @DisplayName("falls back to a plain sentence rather than leaking a stack trace")
    void unknownFailuresStayReadable() {
        assertThat(GitClone.explain(request("ssh://git@host/p.git", null), new IllegalStateException("¯\\_(ツ)_/¯")))
                .isEqualTo("The clone of ssh://git@host/p.git failed.");
    }

    @Test
    @DisplayName("the two host-key policies are named, so choosing one is deliberate")
    void hostKeyPolicyIsExplicit() {
        // The original passed `accept-new` and pointed the known-hosts file at a directory
        // created per clone and deleted after — so every clone was a first contact and every
        // key was accepted. The two halves cancelled out, and nothing said so.
        assertThat(GitClone.HostKeyPolicy.class.getPermittedSubclasses())
                .extracting(Class::getSimpleName)
                .containsExactlyInAnyOrder("AcceptNew", "TrustEveryHost");
    }
}

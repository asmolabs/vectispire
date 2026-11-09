package com.asmolabs.vectispire.common.domain.scans;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What an agent's failure report may carry off the machine that ran the scan.
 *
 * <p>Each case is a message a real failure produces or quotes: JGit naming the URL it was handed,
 * a key parser quoting the line it choked on, an HTTP client quoting its own request.
 */
@DisplayName("a scan's failure reason, scrubbed to leave the machine")
class FailureReasonTest {

    private static final String KEY = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
            QyNTUxOQAAACDx0jmA1pGN1nq6Rq8yUwqK1Fh9iU5Qn4oQ5bq2r8T5MgAAAJgAAAAAAAAA
            -----END OPENSSH PRIVATE KEY-----
            """;

    @Test
    @DisplayName("removes by value the secrets the agent was handed, a key line by line too")
    void secretsByValue() {
        String token = "ghp_0123456789abcdefABCDEF";
        String line = "QyNTUxOQAAACDx0jmA1pGN1nq6Rq8yUwqK1Fh9iU5Qn4oQ5bq2r8T5MgAAAJgAAAAAAAAA";

        String scrubbed = FailureReason.scrub(
                "Clone refused with " + token + "; invalid key line: " + line, List.of(token, KEY));

        assertThat(scrubbed).doesNotContain(token).doesNotContain(line).contains("***");
    }

    @Test
    @DisplayName("removes what has a secret's shape when it knows no value: a PEM block, a URL's user part, a bearer, an envelope")
    void secretsByShape() {
        String scrubbed = FailureReason.scrub(
                "cannot parse " + KEY + " for https://oauth2:glpat-SECRETSECRET@gitlab.example/g/p.git, "
                        + "Authorization: Bearer abcdefghijkl, password=hunter22, key sealed:v1:QUJDREVGRw==");

        assertThat(scrubbed)
                .doesNotContain("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ")
                .doesNotContain("glpat-SECRETSECRET")
                .doesNotContain("abcdefghijkl")
                .doesNotContain("hunter22")
                .doesNotContain("QUJDREVGRw==")
                .contains("[private key removed]")
                .contains("https://***@gitlab.example/g/p.git");
    }

    @Test
    @DisplayName("keeps what the operator needs to act: an SSH login, the host, the sentence")
    void keepsTheMessage() {
        String message = "The host key of ssh://git@gitea:22/team/app.git is not the one listed in known_hosts.";

        assertThat(FailureReason.scrub(message)).isEqualTo(message);
    }

    @Test
    @DisplayName("is one line, bounded, and empty rather than null")
    void oneBoundedLine() {
        assertThat(FailureReason.scrub("clone failed\n2026-09-28 INFO forged entry ")).isEqualTo(
                "clone failed 2026-09-28 INFO forged entry");
        assertThat(FailureReason.scrub("x".repeat(5_000))).hasSize(FailureReason.MAX_LENGTH).endsWith("…");
        assertThat(FailureReason.scrub(null)).isEmpty();
        assertThat(FailureReason.scrub("  ")).isEmpty();
    }
}

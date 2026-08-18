package com.asmolabs.zanshin.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.scanning.scanners.SecretsScanner.SecretFinding;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("scanner output")
class ScannerOutputTest {

    @Nested
    @DisplayName("secrets")
    class Secrets {

        @Test
        @DisplayName("keeps where the secret is, never the secret itself")
        void neverKeepsTheValue() {
            // Copying the plaintext into a finding would put it in the database, in the SARIF
            // exports, in the tickets and in the notifications. A detected secret has to be
            // revoked, not archived — the file and the line are enough to find it.
            String report = """
                    [{"RuleID": "aws-access-token", "Description": "AWS token",
                      "File": "/repo/source/app/config.py", "StartLine": 12,
                      "Fingerprint": "abc123",
                      "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "key = AKIAIOSFODNN7EXAMPLE"}]""";

            SecretFinding finding = SecretsScanner.parse(report).getFirst();

            assertThat(finding.rule()).isEqualTo("aws-access-token");
            assertThat(finding.file()).isEqualTo("app/config.py");
            assertThat(finding.line()).isEqualTo(12);
            assertThat(finding.fingerprint()).isEqualTo("abc123");
            assertThat(Arrays.stream(SecretFinding.class.getRecordComponents()).map(c -> c.getName()))
                    .doesNotContain("secret", "match");
            assertThat(finding.toString()).doesNotContain("AKIAIOSFODNN7EXAMPLE");
        }

        @Test
        @DisplayName("strips the container path, so a file has one identity")
        void pathsAreRelativeToTheTree() {
            assertThat(SecretsScanner.parse("[{\"File\": \"/repo/source/src/main.py\", \"StartLine\": 1}]").getFirst().file())
                    .isEqualTo("src/main.py");
        }

        @Test
        @DisplayName("an absent fingerprint is absent, not an empty string")
        void missingFingerprintIsNull() {
            assertThat(SecretsScanner.parse("[{\"File\": \"a\", \"StartLine\": 1}]").getFirst().fingerprint()).isNull();
        }

        @Test
        @DisplayName("unreadable output yields nothing rather than throwing")
        void malformedOutputIsEmpty() {
            assertThat(SecretsScanner.parse("not json")).isEmpty();
            assertThat(SecretsScanner.parse("{\"not\": \"an array\"}")).isEmpty();
        }
    }

    @Nested
    @DisplayName("container paths")
    class Paths {

        @ParameterizedTest(name = "the target for subPath [{0}] is {1}")
        @CsvSource({"'', /repo/source", "api, /repo/source/api", "/api/, /repo/source/api"})
        void buildsPosixTargets(String subPath, String expected) {
            // Built as POSIX strings, never with the host's separator: the target is a path
            // inside a container, which is Linux whatever machine launched the scan.
            assertThat(ContainerPaths.source(subPath.isEmpty() ? null : subPath)).isEqualTo(expected);
        }

        @Test
        @DisplayName("the rule tree is addressed the same way")
        void buildsRulePaths() {
            assertThat(ContainerPaths.rules("gitleaks", "gitleaks.toml"))
                    .isEqualTo("/repo/rules/gitleaks/gitleaks.toml");
        }

        @ParameterizedTest(name = "[{0}] becomes [{1}]")
        @CsvSource({
            "/repo/source/app/main.tf, app/main.tf",
            "/app/main.tf, app/main.tf",
            "app/main.tf, app/main.tf"
        })
        void reducesToATreeRelativePath(String containerPath, String expected) {
            // Both forms reduce to the same thing, or the same file carries two identities
            // depending on the scanner's version — and two identities is two issues.
            assertThat(ContainerPaths.relativeToSource(containerPath, null)).isEqualTo(expected);
        }
    }

    @Nested
    @DisplayName("the pinned images")
    class Images {

        @Test
        @DisplayName("every scanner image is pinned by digest, never by tag")
        void allPinnedByDigest() {
            // These images are Zanshin's own supply chain. A tool that audits everybody else's
            // cannot pull `:latest` and run whatever comes down.
            assertThat(Arrays.stream(ScannerImages.class.getRecordComponents())
                            .map(component -> {
                                try {
                                    return (String) component.getAccessor().invoke(ScannerImages.PINNED);
                                } catch (Exception e) {
                                    throw new AssertionError(e);
                                }
                            }))
                    .allSatisfy(image -> assertThat(image).contains("@sha256:").doesNotContain(":latest"));
        }
    }
}

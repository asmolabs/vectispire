package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
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

            SecretFinding finding = SecretsScanner.read(report).orElseThrow().getFirst();

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
            assertThat(SecretsScanner.read("[{\"File\": \"/repo/source/src/main.py\", \"StartLine\": 1}]").orElseThrow().getFirst().file())
                    .isEqualTo("src/main.py");
        }

        @Test
        @DisplayName("an absent fingerprint is absent, not an empty string")
        void missingFingerprintIsNull() {
            assertThat(SecretsScanner.read("[{\"File\": \"a\", \"StartLine\": 1}]").orElseThrow().getFirst().fingerprint()).isNull();
        }

        @Test
        @DisplayName("the empty array gitleaks writes on a clean tree is a clean tree")
        void theEmptyArrayIsClean() {
            // The one way to say "no secrets": v8.5.0 to the pinned v8.30.1 write `[]` (measured).
            assertThat(SecretsScanner.read("[]\n")).hasValue(java.util.List.of());
        }

        /**
         * <b>Absent, not empty</b> (decision 0007). Each of these came back as an empty list — or, for
         * the elements that are not objects, as findings with no rule and no file — which resolved
         * every secret issue of the target. The reference set of the Rust port carries the same
         * reports ({@code vectispire-rust/reference/secrets/reports/}).
         */
        @ParameterizedTest(name = "{0}")
        @org.junit.jupiter.params.provider.ValueSource(strings = {
            "this is not json",
            "{\"RuleID\":\"generic-api-key\",\"File\":\"/repo/source/a\"}",
            "",
            "   \n\t\n",
            "[1, \"text\", null, [], {\"RuleID\":\"only-rule\"}]",
            "\uFEFF[{\"RuleID\":\"bom\",\"File\":\"/repo/source/f\",\"StartLine\":1}]",
            "[{\"RuleID\":\"x\",\"File\":\"/repo/source/f\",\"StartLine\":1}] trailing",
            "[{\"RuleID\":\"ctl\",\"File\":\"/repo/source/f\",\"StartLine\":1,\"Description\":\"raw\ttab\"}]",
            "[{\"RuleID\":\"cut\",\"File\":\"/repo/sou",
            "null"
        })
        @DisplayName("a report gitleaks did not write is absent, never an empty list")
        void aReportOfAnotherShapeIsAbsent(String report) {
            assertThat(SecretsScanner.read(report)).isEmpty();
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
            // These images are Vectispire's own supply chain. A tool that audits everybody else's
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

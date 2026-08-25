package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Secondary secret scanner running alongside Gitleaks.
 *
 * <p>Uses the same hermetic execution patterns (no network, rootless workspace mount) and produces
 * normalized {@link SecretsScanner.SecretFinding} records.
 *
 * <p><b>By default this is the same engine as the primary one.</b> {@code ScannerImages} aliases
 * {@code betterleaks} to the pinned {@code gitleaks} digest, and the command below uses the same
 * rule file — so out of the box this is a second, identical pass whose only difference is the
 * report filename. The seam exists so an operator can point {@code betterleaks} at a genuinely
 * different engine; until they do, it buys coverage of exactly nothing and costs one more
 * container per scan. Whoever changes that default should also revisit the shared
 * {@code gitleaks.toml} above, which a different engine has no reason to understand.
 *
 * <p><b>Its failure is not the other scanner's success.</b> This used to be called inside a
 * {@code catch (Exception ignored)}, so a failure here produced Gitleaks' results alone — a
 * non-null list, which decision 0007 defines as "analysed, found nothing" and which therefore
 * <em>resolves</em> leaked-credential findings. The signature below is what stops that being
 * expressible.
 */
public final class BetterleaksScanner {

    private static final String REPORT_FILENAME = "vectispire-betterleaks-report.json";
    private static final String LABEL = "betterleaks (secret detection)";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ContainerRunner runner;
    private final String image;

    public BetterleaksScanner(ContainerRunner runner, String image) {
        this.runner = runner;
        this.image = image;
    }

    public Optional<List<SecretsScanner.SecretFinding>> scan(Workspace workspace, String subPath) {
        ContainerRun request = ContainerRun.of(
                        image,
                        List.of(
                                "detect",
                                "--source=" + ContainerPaths.source(subPath),
                                "--config=" + ContainerPaths.rules("gitleaks", "gitleaks.toml"),
                                "--no-git",
                                "--report-format=json",
                                "--report-path=" + ContainerPaths.MOUNT + "/" + REPORT_FILENAME,
                                "--exit-code=0"),
                        List.of(ContainerRun.Mount.writable(workspace.root().toString(), ContainerPaths.MOUNT)),
                        LABEL)
                .runningAsRoot();

        ContainerRunner.ContainerResult result = runner.run(request);
        if (result.exitCode() != 0) {
            throw ScannerFailureException.exited(LABEL, result.exitCode(), result.stderr());
        }

        Path reportPath = workspace.root().resolve(REPORT_FILENAME);
        try {
            String content = Files.readString(reportPath).strip();
            return Optional.of(content.isEmpty() ? List.of() : parse(content));
        } catch (NoSuchFileException noReport) {
            return Optional.of(List.of());
        } catch (IOException unreadable) {
            // Absent rather than empty, for the reason given on SecretsScanner: a report that
            // could not be read is not a repository without secrets.
            return Optional.empty();
        } finally {
            try {
                Files.deleteIfExists(reportPath);
            } catch (IOException ignored) {
            }
        }
    }

    static List<SecretsScanner.SecretFinding> parse(String content) {
        JsonNode root;
        try {
            root = MAPPER.readTree(content);
        } catch (IOException notJson) {
            return List.of();
        }
        if (!root.isArray()) {
            return List.of();
        }

        List<SecretsScanner.SecretFinding> findings = new ArrayList<>();
        for (JsonNode finding : root) {
            findings.add(new SecretsScanner.SecretFinding(
                    finding.path("RuleID").asText(""),
                    finding.path("Description").asText(""),
                    ContainerPaths.relativeToSource(finding.path("File").asText(""), null),
                    finding.path("StartLine").asInt(0),
                    finding.path("Fingerprint").isTextual() ? finding.get("Fingerprint").asText() : null));
        }
        return findings;
    }
}

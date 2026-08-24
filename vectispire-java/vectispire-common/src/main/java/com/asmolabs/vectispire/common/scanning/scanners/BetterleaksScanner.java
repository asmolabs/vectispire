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

/**
 * Secondary secret scanner based on Betterleaks engine, running alongside Gitleaks.
 *
 * <p>Uses the same hermetic execution patterns (no network, rootless workspace mount) and produces
 * normalized {@link SecretsScanner.SecretFinding} records.
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

    public List<SecretsScanner.SecretFinding> scan(Workspace workspace, String subPath) {
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
            return content.isEmpty() ? List.of() : parse(content);
        } catch (NoSuchFileException noReport) {
            return List.of();
        } catch (IOException unreadable) {
            throw ScannerFailureException.of(LABEL, "The betterleaks report could not be read: " + unreadable.getMessage());
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

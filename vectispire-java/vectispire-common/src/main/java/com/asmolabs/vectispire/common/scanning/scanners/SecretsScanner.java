package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The search for hardcoded secrets.
 *
 * <p><b>The report is written at the workspace root, never inside the scanned tree.</b> It has
 * to live in the mounted volume for the container to write it, and it contains <b>every
 * detected secret in the clear</b> — leaving it in the tree would hand it to the next step,
 * including to a review model. The {@code source/} split is what makes that structural rather
 * than a question of filename.
 *
 * <p>It is deleted the moment it is read, without waiting for the workspace to go: a file of
 * plaintext secrets should exist for exactly as long as it must.
 */
public final class SecretsScanner {

    private static final String REPORT_FILENAME = "vectispire-gitleaks-report.json";
    private static final String LABEL = "gitleaks (secret detection)";
    private static final ObjectReader READER =
            new ObjectMapper().reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final ContainerExecutor runner;
    private final String image;

    public SecretsScanner(ContainerExecutor runner, String image) {
        this.runner = runner;
        this.image = image;
    }

    /**
     * What Vectispire keeps about a secret: where it is, and which rule found it.
     *
     * <p><b>Not its value.</b> The report carries the plaintext; copying it into a finding would
     * put it in the database, in the SARIF exports, in the tickets and in the notifications. A
     * detected secret has to be revoked, not archived — the file and the line are enough to find
     * it.
     *
     * @param fingerprint the one the tool computes itself; useful, and not the secret
     */
    public record SecretFinding(String rule, String description, String file, int line, String fingerprint) {}

    /**
     * The secrets found, or nothing at all.
     *
     * <p><b>Never returns an empty list to mean "I did not run".</b> An empty list means
     * "analysed, no secrets", which resolves the whole backlog for this type — and for the type
     * that carries leaked credentials, a false resolution is the most expensive answer this
     * product can give. A failure leaves {@code Optional.empty()} or throws, and the caller
     * decides (decision 0007).
     *
     * <p><b>Two ways to fail, as {@code SastScanner} has.</b> A non-zero exit throws, because the
     * exit code and the tool's own stderr say more than any reason this class could invent. A
     * report that is missing or is not one gitleaks wrote throws too, with a sentence of this
     * class's own — never a quotation, since the file holds the secrets in the clear. A report the
     * filesystem would not read back comes back empty, and {@link ScanRunner} turns that into the
     * step's recorded failure through {@code ran(…)}. All end in the same place: the artifact
     * stays absent and the backlog is left alone.
     */
    public Optional<List<SecretFinding>> scan(Workspace workspace, String subPath) {
        ContainerRun request = ContainerRun.of(
                        image,
                        List.of(
                                "detect",
                                "--source=" + ContainerPaths.source(subPath),
                                // **The configuration comes from Vectispire, never from the target.**
                                //
                                // Without `--config`, the tool falls back to `.gitleaks.toml`
                                // inside the scanned repository — a file written by whoever is
                                // being audited — and uses it *instead of* its built-in rules. An
                                // empty config with a universal allowlist switched detection off:
                                // exit 0, empty report, empty list. And an empty list means
                                // "analysed, found nothing", hence the silent resolution of every
                                // secret this target ever had, triage included. The repository
                                // closed its own findings.
                                "--config=" + ContainerPaths.rules("gitleaks", "gitleaks.toml"),
                                // The tree is cloned at depth 1, so replaying history would find
                                // almost nothing while costing the time to walk it.
                                "--no-git",
                                "--report-format=json",
                                "--report-path=" + ContainerPaths.MOUNT + "/" + REPORT_FILENAME,
                                // It exits 1 when it finds secrets. That is the expected result,
                                // not a container failure: the code is neutralized and the
                                // results are read from the file. Any *other* non-zero code
                                // remains a real failure and throws.
                                "--exit-code=0"),
                        // Writable: the container has to deposit its report.
                        List.of(ContainerRun.Mount.writable(workspace.root().toString(), ContainerPaths.MOUNT)),
                        LABEL)
                // The workspace is a 0700 directory owned by Vectispire's user: its owner reads it
                // and writes the report, a capability-less root does neither — see ContainerRun.
                .runningAsOwnerOf(workspace.root());

        ContainerRunner.ContainerResult result = runner.run(request);
        if (result.exitCode() != 0) {
            throw ScannerFailureException.exited(LABEL, result.exitCode(), result.stderr());
        }

        Path reportPath = workspace.root().resolve(REPORT_FILENAME);
        try {
            String content = Files.readString(reportPath);
            return Optional.of(read(content).orElseThrow(() -> ScannerFailureException.of(LABEL,
                    "gitleaks exited 0, and its report is not the JSON array of findings it writes — empty, "
                            + "truncated or of another shape; it is not read as a tree without secrets.")));
        } catch (NoSuchFileException noReport) {
            // **No report is not "no secrets".** It was read so, on the strength of the exit code and
            // of versions that write nothing when they find nothing (v8.2.0 does, measured). But
            // gitleaks also exits 0 *without a report* when it cannot write one — after logging
            // "leaks found: 1" (measured on v8.0.0, v8.8.0 and v8.12.0, the report path read-only;
            // v8.14.0 and later exit 1 there). The two cases leave the same nothing behind, and one
            // of them closed every secret issue of the target while the tool said it had found one.
            // The pinned v8.30.1 writes `[]` on a clean tree, so absent costs a clean scan nothing;
            // an image override old enough to write nothing reports a failed step instead of a pass.
            throw ScannerFailureException.of(LABEL, "gitleaks exited 0 without writing its report, which says "
                    + "nothing about the tree: a gitleaks that could not write the file exits 0 too.");
        } catch (IOException unreadable) {
            // **Absent, not empty.** The container ran and may well have found secrets; what
            // failed is reading them back. An empty list here would assert "no secrets" on the
            // strength of a file nobody could open.
            return Optional.empty();
        } finally {
            try {
                Files.deleteIfExists(reportPath);
            } catch (IOException ignored) {
                // The workspace removal will get it; this only shortens the window.
            }
        }
    }

    /**
     * The findings of a report as gitleaks writes it, or absent when the text is not such a report.
     *
     * <p><b>Absent, never an empty list, for anything but {@code []}</b> (decision 0007). Text that is
     * not JSON, JSON that is not an array, an array holding something other than objects, a blank
     * file, a document with something after its end: each used to come back as "analysed, no
     * secrets" — or, for the elements that are not objects, as findings with no rule and no file in
     * place of the real ones — and the backlog then resolved every secret issue of the target, in
     * the one type where a false resolution costs the most. Gitleaks writes an array of objects, and
     * {@code []} when it found nothing (v8.5.0 onwards, measured); nothing else is believed.
     *
     * <p>The fields of an object stay leniently read: a version that drops one is a finding with less
     * detail, not a report to refuse. Package-private so that the reading is pinned without a
     * container, and so that the Rust port's reference set is written from this very function.
     */
    static Optional<List<SecretFinding>> read(String content) {
        JsonNode root;
        try {
            // Trailing tokens refused: a report followed by anything else is not what the tool
            // wrote — two runs' output concatenated, or a stream spliced — and the array in front
            // of it says nothing about what came after.
            root = READER.readTree(content);
        } catch (IOException notJson) {
            return Optional.empty();
        }
        if (root == null || !root.isArray()) {
            return Optional.empty();
        }

        List<SecretFinding> findings = new ArrayList<>(root.size());
        for (JsonNode finding : root) {
            if (!finding.isObject()) {
                return Optional.empty();
            }
            findings.add(new SecretFinding(
                    finding.path("RuleID").asText(""),
                    finding.path("Description").asText(""),
                    // The path the tool returns is the container's; callers expect one relative
                    // to the scanned tree.
                    ContainerPaths.relativeToSource(finding.path("File").asText(""), null),
                    finding.path("StartLine").asInt(0),
                    finding.path("Fingerprint").isTextual() ? finding.get("Fingerprint").asText() : null));
        }
        return Optional.of(List.copyOf(findings));
    }
}

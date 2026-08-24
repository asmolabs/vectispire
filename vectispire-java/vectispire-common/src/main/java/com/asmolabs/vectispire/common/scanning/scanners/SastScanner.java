package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Analysis of the source code itself.
 *
 * <p>Several details below were established against the real image rather than assumed, and
 * each carries something:
 *
 * <ul>
 *   <li><b>The command opens with the tool's own name.</b> The image has no entrypoint — its
 *       {@code Cmd} is {@code ["semgrep", "--help"]} — unlike the IaC checker's. Copying that
 *       one's call shape produces a nonsensical command line and an exit code of 2.
 *   <li><b>{@code --no-rewrite-rule-ids}.</b> With a {@code --config} pointing at a
 *       <em>directory</em>, every {@code check_id} is prefixed with the rule file's relative
 *       path. Reorganizing the rule tree would therefore rename every identifier — and the
 *       identifier enters an issue's fingerprint, so <b>the whole SAST backlog would resolve
 *       and reappear from scratch, triage lost</b>.
 *   <li><b>No error flag.</b> A scan exits 0 when it finds something; only the CI subcommand
 *       exits 1. There is thus no soft-fail equivalent to pass, and any non-zero code is a real
 *       failure.
 *   <li><b>Network cut</b>, like the other two: the rules are on disk, and the metrics and
 *       version checks are switched off so startup is not spent in a DNS timeout.
 *   <li><b>A memory cap under the container's</b>, so a large repository degrades through the
 *       tool's own limiter rather than being killed with 137 by the out-of-memory killer.
 * </ul>
 */
public final class SastScanner {

    /**
     * The share of failed files past which the result counts as "did not run".
     *
     * <p>The tool exits 0 when individual files time out, so a run where most of the repository
     * was skipped is <b>indistinguishable from a clean one</b> by its exit code alone — and
     * reading it as clean would resolve the target's whole SAST backlog.
     */
    private static final double MAX_ERROR_RATIO = 0.25;

    private static final String LABEL = "semgrep (source code analysis)";

    private final ContainerRunner runner;
    private final String image;

    public SastScanner(ContainerRunner runner, String image) {
        this.runner = runner;
        this.image = image;
    }

    /**
     * @param ruleId enters the fingerprint: it must not move
     * @param category {@code security} or a quality category — this is what decides where the
     *     finding goes, and whether it can fail a build
     * @param message for a SAST finding, the message <em>is</em> the finding
     */
    public record SastFinding(
            String ruleId, String category, Severity severity, String confidence, String file, int line, String message) {}

    /**
     * The findings, or empty when the tool ended well and covered too little to be read.
     *
     * <p><b>A failure is thrown, not returned empty.</b> Both cases used to arrive here as an
     * absent result, so a refused rule file, a timeout and a thin report were one indistinguishable
     * outcome — and the caller could only describe it as "did not run, or covered too few files".
     * A {@link ScannerFailureException} carries what actually happened, and the step records it.
     */
    public Optional<List<SastFinding>> scan(Workspace workspace, String subPath) {
        // `rules/semgrep`, not `rules`: the workspace also carries the secrets scanner's
        // configuration, and pointing at the parent directory would walk a tree that is not
        // this tool's.
        String rules = ContainerPaths.rules("semgrep");

        ContainerRunner.ContainerResult result = runner.run(ContainerRun.of(
                        image,
                        List.of(
                                "semgrep",
                                "scan",
                                "--config=" + rules,
                                "--no-rewrite-rule-ids",
                                // **The target does not choose what gets looked at.** The tool
                                // honours the analysed tree's `.gitignore` by default — and that
                                // tree is a clone of the scanned repository, hence written by
                                // whoever is being audited. A committed `*` excluded everything,
                                // and the step returned an empty success.
                                "--no-git-ignore",
                                "--json",
                                "--metrics=off",
                                "--disable-version-check",
                                "--quiet",
                                "--timeout=30",
                                "--timeout-threshold=3",
                                "--max-target-bytes=1000000",
                                "--max-memory=1500",
                                "--jobs=2",
                                ContainerPaths.source(subPath)),
                        List.of(ContainerRun.Mount.readOnly(workspace.root().toString(), ContainerPaths.MOUNT)),
                        LABEL)
                .runningAsRoot());

        // **The refusal is read before the exit code is judged.** Semgrep reports a bad
        // configuration on *stdout*, inside the JSON, and leaves stderr empty — so the generic
        // "exited with 7" carries no output at all and does not name the file. That cost a
        // bisection through 1118 rule files to answer a question the scanner had already
        // answered.
        if (result.exitCode() != 0) {
            throw ScannerFailureException.exited(LABEL, result.exitCode(), diagnosis(result));
        }

        Optional<JsonNode> payload = ContainerRunner.parseJson(result, LABEL, List.of(0));
        if (payload.isEmpty() || mostlyFailed(payload.get())) {
            // The one outcome that is genuinely "we cannot tell": the tool ended well and its
            // report covers too little to be read as a clean tree. Absent, and the caller says so.
            return Optional.empty();
        }
        return Optional.of(findings(payload.get(), subPath));
    }

    /**
     * What the tool said about its own failure, wherever it put it.
     *
     * <p>A refused configuration produces {@code "errors": [{"type": "InvalidRuleSchemaError"},
     * {"message": "invalid configuration file found (1 configs were invalid)"}]} on stdout and
     * nothing on stderr. Reporting the empty stream would be reporting that the scanner said
     * nothing, which is the opposite of what happened.
     */
    private static String diagnosis(ContainerRunner.ContainerResult result) {
        String stderr = result.stderr() == null ? "" : result.stderr().strip();
        try {
            JsonNode payload = ContainerRunner.parseJson(
                            new ContainerRunner.ContainerResult(result.stdout(), "", 0), LABEL, List.of(0))
                    .orElse(null);
            if (payload == null || !payload.path("errors").isArray()) {
                return stderr;
            }
            StringBuilder said = new StringBuilder();
            for (JsonNode error : payload.path("errors")) {
                String type = error.path("type").asText("");
                String message = error.path("message").asText("");
                if (!type.isBlank() || !message.isBlank()) {
                    said.append(said.isEmpty() ? "" : "; ").append(type.isBlank() ? message : type)
                            .append(type.isBlank() || message.isBlank() ? "" : ": " + message);
                }
            }
            return said.isEmpty() ? stderr : said.toString();
        } catch (RuntimeException unreadable) {
            // The payload is whatever a failing scanner happened to print. If it cannot be read
            // as JSON, the other stream is still better than nothing.
            return stderr;
        }
    }

    /**
     * Did the analysis fail on enough files to be worth nothing?
     *
     * <p>The report carries its own errors and the list of files actually analysed; the exit
     * code says nothing. Without reading them, a repository where four files in five timed out
     * reads as "analysed, almost nothing found".
     */
    static boolean mostlyFailed(JsonNode payload) {
        int errors = payload.path("errors").isArray() ? payload.path("errors").size() : 0;
        int scanned = payload.path("paths").path("scanned").isArray() ? payload.path("paths").path("scanned").size() : 0;

        // **Zero files examined is not a clean tree, it is an analysis that did not happen** —
        // and that was the hole. The check returned early on "no errors" before looking at
        // coverage, so a run that had excluded everything reported no findings, hence "analysed,
        // found nothing", hence the resolution of the target's whole SAST and quality backlog.
        //
        // File selection is influenceable from the repository: the tool honours its own ignore
        // file and, by default, `.gitignore` — and the tree is always a git clone. A committed
        // `*` was enough to switch the step off while it looked like a success.
        if (scanned == 0) {
            return true;
        }
        if (errors == 0) {
            return false;
        }
        return (double) errors / (errors + scanned) > MAX_ERROR_RATIO;
    }

    static List<SastFinding> findings(JsonNode payload, String subPath) {
        JsonNode results = payload.path("results");
        if (!results.isArray()) {
            return List.of();
        }

        List<SastFinding> findings = new ArrayList<>(results.size());
        for (JsonNode entry : results) {
            JsonNode extra = entry.path("extra");
            JsonNode metadata = extra.path("metadata");

            findings.add(new SastFinding(
                    entry.path("check_id").asText("unknown"),
                    // Absent means "security": that is the cautious reading. Filing an unknown
                    // finding as quality would make it unable to fail a gate — quality never
                    // blocks, by design.
                    metadata.path("category").isTextual() ? metadata.get("category").asText() : "security",
                    severityOf(extra.path("severity").asText(null)),
                    metadata.path("confidence").isTextual() ? metadata.get("confidence").asText() : null,
                    ContainerPaths.relativeToSource(entry.path("path").asText(""), subPath),
                    entry.path("start").path("line").asInt(0),
                    extra.path("message").asText("")));
        }
        return List.copyOf(findings);
    }

    /**
     * The tool's vocabulary into Vectispire's.
     *
     * <p>An explicit table and not a lowercase conversion: {@code "ERROR"} lowercased is
     * {@code error}, which belongs to no policy threshold. The value would then propagate
     * silently into the ordering, the summary, the gate and the SARIF export.
     *
     * <p>The default is {@code MEDIUM} rather than {@code UNKNOWN}: an unrecognized level from a
     * tool that only emits three is more likely a new level than an absent one, and
     * {@code UNKNOWN} ranks below {@code LOW} — which would quietly exempt it from every gate.
     */
    static Severity severityOf(String severity) {
        if (severity == null) {
            return Severity.MEDIUM;
        }
        return switch (severity) {
            case "ERROR" -> Severity.HIGH;
            case "WARNING" -> Severity.MEDIUM;
            case "INFO" -> Severity.LOW;
            default -> Severity.MEDIUM;
        };
    }
}

package com.asmolabs.zanshin.common.scanning.scanners;

import com.asmolabs.zanshin.common.scanning.ContainerRun;
import com.asmolabs.zanshin.common.scanning.ContainerRunner;
import com.asmolabs.zanshin.common.scanning.Workspace;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Analysis of infrastructure manifests — Terraform, Kubernetes, Dockerfiles.
 *
 * <p><b>Returns empty and never an empty list when the checker fails.</b> That distinction
 * decides the fate of the backlog: an empty list means "analysed, clean", which ingestion reads
 * as permission to resolve every IaC issue on the target. A crash would therefore declare a
 * repository fixed. An absent result says nothing was looked at, and the backlog is left alone
 * (decision 0007).
 *
 * <p>The caution is not theoretical: this checker's command line and output vary by version and
 * by which frameworks it detects, and a failure here must not sink the whole scan.
 */
public final class IacScanner {

    private static final String LABEL = "checkov (IaC analysis)";

    private final ContainerRunner runner;
    private final String image;

    public IacScanner(ContainerRunner runner, String image) {
        this.runner = runner;
        this.image = image;
    }

    /**
     * @param checkId the control's identifier — {@code CKV_AWS_20} and the like
     * @param resource the resource concerned: {@code aws_s3_bucket.example}
     */
    public record IacFinding(String checkId, String checkName, String file, int line, String guideline, String resource) {}

    public Optional<List<IacFinding>> scan(Workspace workspace, String subPath) {
        try {
            ContainerRunner.ContainerResult result = runner.run(ContainerRun.of(
                            image,
                            // `--soft-fail`: it exits 1 when a control fails. That is the
                            // expected result, not a container failure — the same reason the
                            // secrets scanner neutralizes its own exit code.
                            List.of("-d", ContainerPaths.source(subPath), "-o", "json", "--soft-fail", "--compact"),
                            List.of(ContainerRun.Mount.readOnly(workspace.root().toString(), ContainerPaths.MOUNT)),
                            LABEL)
                    .runningAsRoot());

            Optional<JsonNode> payload = ContainerRunner.parseJson(result, LABEL, List.of(0));
            return payload.map(node -> findings(node, subPath));
        } catch (RuntimeException failure) {
            // Deliberately broad: this checker's output varies enough between versions that a
            // failure is plausible without the rest of the scan having to suffer. Empty — never
            // an empty list — for the reason at the top of this file.
            return Optional.empty();
        }
    }

    private static List<IacFinding> findings(JsonNode payload, String subPath) {
        List<IacFinding> findings = new ArrayList<>();

        // It returns **one** report object when a single framework is detected, and a *list*
        // when several are — Terraform and Kubernetes in the same repository, for instance.
        // Handling both shapes is what stops a mixed repository from reporting nothing.
        Iterable<JsonNode> reports = payload.isArray() ? payload : List.of(payload);
        for (JsonNode report : reports) {
            for (JsonNode check : report.path("results").path("failed_checks")) {
                findings.add(new IacFinding(
                        check.path("check_id").asText("unknown"),
                        check.path("check_name").asText(""),
                        // It returns a path relative to its target, sometimes with a leading
                        // slash. Both forms are reduced to a path relative to the scanned tree,
                        // or the same file would carry two identities depending on the version.
                        ContainerPaths.relativeToSource(check.path("file_path").asText(""), subPath),
                        check.path("file_line_range").path(0).asInt(0),
                        check.path("guideline").isTextual() ? check.get("guideline").asText() : null,
                        check.path("resource").isTextual() ? check.get("resource").asText() : null));
            }
        }
        return List.copyOf(findings);
    }
}

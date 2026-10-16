package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.Workspace;
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
                    .runningAsOwnerOf(workspace.root()));

            Optional<JsonNode> payload = ContainerRunner.parseJson(result, LABEL, List.of(0));
            return payload.flatMap(node -> findings(node, subPath));
        } catch (RuntimeException failure) {
            // Deliberately broad: this checker's output varies enough between versions that a
            // failure is plausible without the rest of the scan having to suffer. Empty — never
            // an empty list — for the reason at the top of this file.
            return Optional.empty();
        }
    }

    /**
     * The failed controls, or absent when the payload is not a report checkov wrote.
     *
     * <p><b>Three shapes are checkov's, measured on the pinned 3.3.9</b>: one report object
     * ({@code check_type}, {@code results}, {@code summary}) when one framework is detected, a list of
     * them when several are — Terraform and Kubernetes in the same repository, for instance — and,
     * when there is nothing to check, a bare summary ({@code passed}, {@code failed}, …,
     * {@code resource_count}, {@code checkov_version}) with no {@code results} at all. The last is a
     * clean answer: an empty list.
     *
     * <p><b>Anything else is absent, never an empty list</b> (decision 0007). Every path through this
     * method used to end in a list: a report whose {@code results} were missing, a JSON string, an
     * empty array — each read as "no control failed" and resolved the target's whole IaC backlog.
     *
     * <p><b>Parsing errors are not read as a failure</b>, though a manifest checkov cannot parse is
     * checked against nothing and its issues resolve. Measured on 3.3.9, its {@code terraform_plan}
     * framework lists every JSON file that does not parse — a broken {@code package.json}, a test
     * fixture — as a parsing error with {@code resource_count: 0}, so a rule on those counts would
     * fail the IaC step of any repository carrying one, at every scan. Closing it needs the
     * parsing errors read per framework against the files that framework owns; it is not done here.
     */
    static Optional<List<IacFinding>> findings(JsonNode payload, String subPath) {
        if (payload.isObject() && !payload.has("results")) {
            return isBareSummary(payload) ? Optional.of(List.of()) : Optional.empty();
        }
        Iterable<JsonNode> reports;
        if (payload.isArray() && !payload.isEmpty()) {
            reports = payload;
        } else if (payload.isObject()) {
            reports = List.of(payload);
        } else {
            return Optional.empty();
        }

        List<IacFinding> findings = new ArrayList<>();
        for (JsonNode report : reports) {
            JsonNode failed = report.path("results").path("failed_checks");
            if (!report.isObject() || !failed.isArray()) {
                return Optional.empty();
            }
            for (JsonNode check : failed) {
                if (!check.isObject()) {
                    return Optional.empty();
                }
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
        return Optional.of(List.copyOf(findings));
    }

    /** What checkov prints when no framework found anything to check. */
    private static boolean isBareSummary(JsonNode payload) {
        return payload.path("resource_count").isIntegralNumber() && payload.path("checkov_version").isTextual();
    }
}

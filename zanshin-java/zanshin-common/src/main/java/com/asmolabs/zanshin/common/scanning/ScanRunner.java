package com.asmolabs.zanshin.common.scanning;

import com.asmolabs.zanshin.common.scanning.scanners.DependencyScanner;
import com.asmolabs.zanshin.common.scanning.scanners.IacScanner;
import com.asmolabs.zanshin.common.scanning.scanners.SastScanner;
import com.asmolabs.zanshin.common.scanning.scanners.ScannerImages;
import com.asmolabs.zanshin.common.scanning.scanners.SecretsScanner;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Running a scan: clone, launch the scanners, return the raw output.
 *
 * <p><b>No database, no entity, no encryption key, no setting.</b> It takes a task and returns
 * artifacts. That is not tidiness but the constraint that makes agents possible: a remote agent
 * has a Docker socket and a temporary directory, not access to the control plane. The only code
 * it can run is code of this shape — and this is exactly the code that will run there, in the
 * same order.
 *
 * <p><b>Each step is independent of the others.</b> One scanner failing does not sink the scan:
 * its artifact stays absent, which ingestion reads as "not looked at" rather than "found
 * nothing". Only the clone is blocking — with no tree there is nothing to analyse.
 */
public final class ScanRunner {

    private final ContainerRunner containers;
    private final DependencyScanner dependencies;
    private final SecretsScanner secrets;
    private final IacScanner iac;
    private final SastScanner sast;
    private final RulePlacement rules;
    private final RulePlacement.RuleSetProvider ruleSets;
    private final GitClone.HostKeyPolicy hostKeys;
    private final Clock clock;

    /**
     * @param ruleSets how this executor obtains an uploaded rule set. Injected rather than
     *     constructed: the built-in worker reads it from the database, a remote agent fetches it
     *     over HTTP. This layer can know neither — the architecture suite forbids it from
     *     reaching persistence, and that prohibition is what lets the same runner serve both
     *     sides
     */
    public ScanRunner(
            ContainerRunner containers,
            ScannerImages images,
            Path bundledRules,
            RulePlacement.RuleSetProvider ruleSets,
            GitClone.HostKeyPolicy hostKeys,
            Clock clock) {
        this.containers = containers;
        this.dependencies = new DependencyScanner(containers, images);
        this.secrets = new SecretsScanner(containers, images.gitleaks());
        this.iac = new IacScanner(containers, images.checkov());
        this.sast = new SastScanner(containers, images.semgrep());
        this.rules = new RulePlacement(bundledRules);
        this.ruleSets = ruleSets;
        this.hostKeys = hostKeys;
        this.clock = clock;
    }

    public ScanArtifacts run(ScanTask task) {
        Instant started = clock.instant();

        return switch (task.target()) {
            case ScanTask.Target.Image image -> runImage(task, image, started);
            case ScanTask.Target.Repository repository -> runRepository(task, repository, started);
        };
    }

    private ScanArtifacts runRepository(ScanTask task, ScanTask.Target.Repository repository, Instant started) {
        return Workspace.withWorkspace(workspace -> {
            ScanArtifacts.Builder artifacts = ScanArtifacts.builder();

            // Blocking, and the only step that is: with no tree there is nothing to analyse,
            // and carrying on would produce empty lists that resolve the whole backlog.
            GitClone.clone(new GitClone.Request(
                    repository.url(), repository.branch(), workspace.source(),
                    repository.privateKey(), Duration.ofMinutes(5), hostKeys));

            String subPath = repository.subPath();

            if (task.runs(ScanTask.Step.DEPENDENCIES)) {
                step(artifacts, "dependencies", () -> {
                    Optional<JsonNode> sbom = dependencies.sbomOfDirectory(workspace, subPath);
                    sbom.ifPresent(document -> {
                        artifacts.sbom(document);
                        dependencies.matchSbom(workspace, document.toString()).ifPresent(artifacts::dependencies);
                    });
                });
            }

            // **Placed before the scanners, not inside the SAST step.** The secrets scanner
            // needs them too: its configuration has to come from here rather than from the
            // analysed tree, and copying it only for the source analyser left the first one
            // reading the target's own.
            rules.placeBundled(workspace);

            if (task.runs(ScanTask.Step.SECRETS)) {
                step(artifacts, "secrets", () -> artifacts.secrets(secrets.scan(workspace, subPath)));
            }
            if (task.runs(ScanTask.Step.IAC)) {
                step(artifacts, "IaC", () -> iac.scan(workspace, subPath).ifPresent(artifacts::iac));
            }
            if (task.runs(ScanTask.Step.SAST)) {
                step(artifacts, "SAST", () -> {
                    // **Inside the step, and before the scan.** A rule set that cannot be
                    // obtained, or a configured directory that cannot be read, must fail SAST
                    // alone — not the SBOM, not the secrets — and must leave its result absent
                    // rather than let the analyser run with the bundled rules and report a
                    // clean, shorter list.
                    rules.placeRuleSet(
                            workspace, task.rulesHash(), ruleSets, RulePlacement.environmentDirectory().orElse(null));
                    sast.scan(workspace, subPath).ifPresent(artifacts::sast);
                });
            }

            return artifacts.build(Duration.between(started, clock.instant()));
        });
    }

    /**
     * Scanning a container image.
     *
     * <p><b>One step only.</b> There is no tree to clone. Secrets, IaC and source analysis do
     * not apply — they look inside source code, not image layers — and declaring them scanned
     * would silently resolve their whole history for this target. They stay absent: "we did not
     * look", which is the truth.
     *
     * <p>End of life and licences, on the other hand, are read from the SBOM produced here —
     * and an image is precisely where the first has most value, since it sees the base
     * distribution no package-level lookup would find.
     */
    private ScanArtifacts runImage(ScanTask task, ScanTask.Target.Image image, Instant started) {
        ScanArtifacts.Builder artifacts = ScanArtifacts.builder();

        // **A workspace, now.** None was needed while the cataloguer read the image from the
        // registry with the Docker socket mounted; that mount was precisely the problem. The
        // image is exported into this workspace by Zanshin, and the cataloguer sees one
        // read-only file.
        Workspace.withWorkspace(workspace -> {
            step(artifacts, "dependencies", () -> {
                Optional<JsonNode> sbom = dependencies.sbomOfImage(
                        workspace, image.reference().format(), image.platform());
                sbom.ifPresent(document -> {
                    artifacts.sbom(document);
                    dependencies.matchStandaloneSbom(document.toString()).ifPresent(artifacts::dependencies);
                });
            });
            return null;
        });

        return artifacts.build(Duration.between(started, clock.instant()));
    }

    /** Is the daemon reachable? Asked before claiming a scan rather than in the middle of one. */
    public boolean canScan() {
        return containers.isAvailable();
    }

    /**
     * Runs a step, and remembers its failure without interrupting the scan.
     *
     * <p>The artifact stays absent: that is what tells "not looked at" from "found nothing", and
     * what stops one scanner's failure from resolving the whole backlog of its type.
     */
    private static void step(ScanArtifacts.Builder artifacts, String name, Runnable body) {
        try {
            body.run();
        } catch (RuntimeException failure) {
            artifacts.failed(name, failure.getMessage() == null ? failure.toString() : failure.getMessage());
        }
    }
}

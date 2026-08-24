package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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
    private final com.asmolabs.vectispire.common.scanning.scanners.BetterleaksScanner betterleaks;
    private final IacScanner iac;
    private final SastScanner sast;
    private final RulePlacement rules;
    private final RulePlacement.RuleSetProvider ruleSets;
    private final GitClone.HostKeyPolicy hostKeys;

    /**
     * What to do for a repository that carries no deployment key.
     *
     * <p>Injected rather than decided here, for the same reason the rule provider is: this class
     * runs on both sides and the two sides answer differently. A remote agent in
     * {@code CredentialsMode.LOCAL} is supposed to use its own git access — that is the whole
     * meaning of the mode — while the built-in worker runs inside the control plane, where
     * borrowing the host's identity would let any target added to Vectispire be cloned with it.
     */
    private final GitClone.WithoutKey withoutKey;
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
            GitClone.WithoutKey withoutKey,
            Clock clock) {
        this.containers = containers;
        this.dependencies = new DependencyScanner(containers, images);
        this.secrets = new SecretsScanner(containers, images.gitleaks());
        this.betterleaks = new com.asmolabs.vectispire.common.scanning.scanners.BetterleaksScanner(containers, images.betterleaks());
        this.iac = new IacScanner(containers, images.checkov());
        this.sast = new SastScanner(containers, images.semgrep());
        this.rules = new RulePlacement(bundledRules);
        this.ruleSets = ruleSets;
        this.hostKeys = hostKeys;
        this.withoutKey = withoutKey;
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
                    repository.privateKey(), Duration.ofMinutes(5), hostKeys, withoutKey));

            String subPath = repository.subPath();

            // **Not a step, and not wrapped in one.** Reading a manifest is a file read, not an
            // analysis: it produces no finding, resolves no backlog, and its absence is an
            // ordinary property of a repository rather than a scanner that failed. Wrapping it
            // would put "no pom.xml" in the same list as "Semgrep timed out".
            ProjectManifest.read(workspace.source().resolve(subPath)).ifPresent(artifacts::project);

            if (task.runs(ScanTask.Step.DEPENDENCIES)) {
                step(artifacts, "dependencies", () -> {
                    JsonNode sbom = ran(
                            dependencies.sbomOfDirectory(workspace, subPath),
                            "the inventory of the tree's dependencies could not be taken.");
                    artifacts.sbom(sbom);
                    artifacts.dependencies(ran(
                            dependencies.matchSbom(workspace, sbom.toString()),
                            "the inventory was taken but could not be matched against known vulnerabilities."));
                });
            }

            // **Placed before the scanners, not inside the SAST step.** The secrets scanner
            // needs them too: its configuration has to come from here rather than from the
            // analysed tree, and copying it only for the source analyser left the first one
            // reading the target's own.
            rules.placeBundled(workspace);

            if (task.runs(ScanTask.Step.SECRETS)) {
                step(artifacts, "secrets", () -> {
                    List<SecretsScanner.SecretFinding> allSecrets = new java.util.ArrayList<>(secrets.scan(workspace, subPath));
                    try {
                        allSecrets.addAll(betterleaks.scan(workspace, subPath));
                    } catch (Exception ignored) {
                    }
                    artifacts.secrets(allSecrets);
                });
            }
            if (task.runs(ScanTask.Step.IAC)) {
                step(artifacts, "IaC", () -> artifacts.iac(ran(
                        iac.scan(workspace, subPath),
                        "the infrastructure manifest check did not complete.")));
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
                    artifacts.sast(ran(
                            sast.scan(workspace, subPath),
                            "the source analysis did not run, or covered too few files to be worth reading."));
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
        // image is exported into this workspace by Vectispire, and the cataloguer sees one
        // read-only file.
        Workspace.withWorkspace(workspace -> {
            step(artifacts, "dependencies", () -> {
                JsonNode sbom = ran(
                        dependencies.sbomOfImage(workspace, image.reference().format(), image.platform()),
                        "the image could not be fetched, or its dependencies could not be inventoried.");
                artifacts.sbom(sbom);
                artifacts.dependencies(ran(
                        dependencies.matchStandaloneSbom(sbom.toString()),
                        "the inventory was taken but could not be matched against known vulnerabilities."));
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

    /**
     * The result of a scanner that reports its own failure by returning nothing.
     *
     * <p><b>An absent result used to be dropped here in silence.</b> Every scanner below returns
     * {@code Optional.empty()} rather than an empty list when its analysis did not happen —
     * timeout, non-zero exit, a report covering no file — and the call sites consumed that with
     * {@code ifPresent}. The artifact then stayed absent, which is correct and is what protects
     * the backlog, but {@code failures} stayed empty too: the scan was recorded {@code
     * completed}, with no error to show, and an operator reading an empty SAST list saw a clean
     * repository instead of a step that never ran. {@link ScanArtifacts#observedNothing()} does
     * not catch it either — it asks whether <em>every</em> step is absent, and the other three
     * had produced findings.
     *
     * <p>Raised as an exception so the failure travels through {@link #step} rather than through
     * a second mechanism: one place decides what a failed step does, and the artifact is left
     * absent by the same path.
     */
    private static <T> T ran(Optional<T> result, String reason) {
        return result.orElseThrow(() -> new StepDidNotRun(reason));
    }

    /** Carries the reason to {@link #step}; never leaves this class. */
    private static final class StepDidNotRun extends RuntimeException {
        StepDidNotRun(String reason) {
            super(reason);
        }
    }
}

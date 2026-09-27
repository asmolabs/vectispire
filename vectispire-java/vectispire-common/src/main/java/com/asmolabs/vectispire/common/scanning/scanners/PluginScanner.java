package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.plugins.ImageDigest;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.sarif.InvalidSarifException;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.domain.sarif.SarifReport;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Running a plugin: a third-party image, confined exactly like the scanners Vectispire ships.
 *
 * <p><b>No exception to the closed shape.</b> {@link ContainerRun#of} — no network, no capability,
 * {@code no-new-privileges}, a read-only root, {@code noexec} scratch, the scanner limits, a label —
 * through the same {@link ContainerRunner} and the same Docker endpoint as Syft or Semgrep; there is
 * no option to mount the socket, so there is none for a plugin either. What differs is only what
 * the manifest may say, and each of its widenings is spelled here where it is applied:
 *
 * <ul>
 *   <li><b>Only the analysed tree is mounted</b>, read-only, at {@value PluginManifest#SOURCE}. Not
 *       the workspace: its root holds the secrets report in the clear and the SBOM, and a plugin is
 *       code somebody else wrote.
 *   <li><b>One writable directory</b>, empty, at {@value PluginManifest#OUTPUT}, <b>that cannot hold
 *       more than the scanner output ceiling</b> — a size-limited tmpfs volume kept by a holder
 *       container, never a directory of the host ({@link ContainerRun.BoundedOutput}). A bind mount
 *       carried no size, and a plugin could fill the executor's disk through it. The report is read
 *       from there, not from stdout: a plugin can log what it likes without corrupting its SARIF. A
 *       plugin that filled the directory had a write refused, and its report is not believed.
 *   <li><b>A declared signer is verified before the image is pulled</b>
 *       ({@link ImageSignatureVerifier}); an executor configured to require one runs no plugin
 *       whose manifest declares none.
 *   <li><b>As the workspace's owner, never root</b> — the Grype lesson: what root writes into a mount
 *       is root's on the host, and the unprivileged process cannot delete it afterwards. A host that
 *       reports no owner cannot run a plugin at all, rather than run it as root — and neither can
 *       a Vectispire that itself runs as root, whose workspace is root's: running as its owner
 *       would then be running as root, the one thing this rule exists to prevent.
 *   <li><b>The network only when the manifest asks</b>, with the justification the governor wrote.
 *   <li><b>A timeout no longer than the scanners'</b>; the memory, process and CPU ceilings are the
 *       scanner limits', unchanged.
 * </ul>
 *
 * <p><b>The report is read like anything else a stranger wrote.</b> Not through a link — the daemon
 * archives a link as a link, and one is refused — only a regular file, and only up to the output
 * ceiling, checked on the archive's header before its content is read. Then {@link SarifReport}'s
 * guards.
 *
 * <p><b>Returns empty, never an empty list, when the plugin did not analyse</b> (decision 0007): a
 * report with no run, or a run that says it computed no results. A failure it can explain — an
 * undeclared exit code, no report, a report refused, a run that says it failed — is thrown, and
 * the runner records the reason.
 */
public final class PluginScanner {

    /** Where the workspace keeps what the plugin machinery needs — a signer's key — outside the tree. */
    static final String PLUGINS_SUBDIR = "plugins";

    /**
     * The holder of a plugin's output directory: busybox 1.37, by the digest of its
     * multi-architecture index. It only sleeps and, stopped, prints {@code df}; relocated to the
     * plugin registry like a plugin's image, so an estate pulling through a mirror mirrors it too.
     */
    public static final String OUTPUT_HOLDER =
            "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

    /** A process killed by {@code SIGXFSZ}: it wrote a file past its {@code fsize} limit. */
    static final int FILE_TOO_LARGE_EXIT = 128 + 25;

    /**
     * What an executor decides about plugins for itself, whatever the control plane sends it.
     *
     * @param registryMirror the internal registry plugin images are pulled from, or blank for their
     *     own — see {@link ImageDigest#relocate}
     * @param signatureRequired run no plugin whose manifest declares no signer. <b>The executor's
     *     setting, not the control plane's</b>: the host that runs the code is the one at stake, and an
     *     agent's operator may refuse unsigned code whatever the governor registered
     *     ({@code VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED})
     */
    public record Settings(String registryMirror, boolean signatureRequired) {

        public static final Settings DEFAULT = new Settings(null, false);

        public Settings {
            registryMirror = registryMirror == null || registryMirror.isBlank()
                    ? null
                    : ImageDigest.requireMirror(registryMirror);
        }
    }

    private final ContainerRunner runner;
    private final Settings settings;
    private final ImageSignatureVerifier verifier;
    private final Function<Path, Optional<String>> owners;

    /** A mirror, and signatures verified where declared but not required. */
    public PluginScanner(ContainerRunner runner, String registryMirror) {
        this(runner, new Settings(registryMirror, false));
    }

    public PluginScanner(ContainerRunner runner, Settings settings) {
        this(runner, settings, ContainerRun::ownerOf);
    }

    /**
     * @param owners how a directory's {@code uid:gid} is read. Replaceable because the answer is
     *     whoever runs the build: the CI's job container is root, a developer is not, and a test of
     *     either rule must not depend on which of the two ran it
     */
    public PluginScanner(ContainerRunner runner, Settings settings, Function<Path, Optional<String>> owners) {
        this.runner = runner;
        this.settings = settings == null ? Settings.DEFAULT : settings;
        this.verifier = new ImageSignatureVerifier(runner);
        this.owners = owners;
    }

    /**
     * @param toolName the SARIF driver's name, for provenance
     * @param findings what the plugin reported, possibly none — which resolves its issues
     */
    public record PluginReport(String toolName, String toolVersion, List<SarifFinding> findings) {}

    /**
     * Runs the plugin over {@code analysedRoot}.
     *
     * @param analysedRoot the directory the scan is limited to, already proven to lie inside the
     *     clone ({@code SourceFiles.within}) and to exist
     */
    public Optional<PluginReport> scan(Workspace workspace, Path analysedRoot, PluginManifest manifest) {
        String label = "plugin " + manifest.id();
        if (manifest.signature() == null && settings.signatureRequired()) {
            throw ScannerFailureException.of(label, "This executor runs only plugins whose manifest declares who signed "
                    + "their image (VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED), and this one declares nobody; it was not run.");
        }
        String owner = owners.apply(workspace.root()).orElseThrow(() -> ScannerFailureException.of(label,
                "This host reports no owner for the workspace, so the plugin cannot run as an unprivileged user; "
                        + "it is not run as root instead."));
        if (owner.startsWith("0:")) {
            throw ScannerFailureException.of(label,
                    "Vectispire runs as root here, so the workspace is root's and the plugin would run as root; "
                            + "it is not run. Run Vectispire as an unprivileged user, as its images do (1000:1000).");
        }

        String image = ImageDigest.relocate(manifest.image(), settings.registryMirror());
        if (manifest.signature() != null) {
            // Before the run, hence before the pull: an image nobody verified is not even fetched.
            verifier.verify(image, manifest.signature(),
                    workspace.root().resolve(PLUGINS_SUBDIR).resolve(manifest.id() + "-signer"), owner, label,
                    ImageDigest.relocate(ImageSignatureVerifier.COSIGN, settings.registryMirror()));
        }

        long capacity = runner.outputBytes();
        ContainerRun run = ContainerRun.of(
                        image,
                        manifest.command(PluginManifest.SOURCE, PluginManifest.OUTPUT + "/" + manifest.output()),
                        List.of(ContainerRun.Mount.readOnly(analysedRoot.toString(), PluginManifest.SOURCE)),
                        label)
                .runningAs(owner)
                .withBoundedOutput(new ContainerRun.BoundedOutput(PluginManifest.OUTPUT, capacity,
                        ImageDigest.relocate(OUTPUT_HOLDER, settings.registryMirror()), manifest.output()));
        if (manifest.network()) {
            // The governor's declared exception, justified in the manifest and in the audit log.
            run = run.withNetwork();
        }
        if (manifest.timeoutSeconds() != null) {
            run = run.withTimeout(Duration.ofSeconds(manifest.timeoutSeconds()));
        }

        ContainerRunner.ContainerResult result = runner.run(run);
        ContainerRunner.CollectedOutput output = result.output().orElseThrow(() -> ScannerFailureException.of(label,
                "Its output directory was not read back."));
        // Before the exit code: a plugin refused a write usually exits on an error, and the directory
        // being full is the explanation its own words would only hint at.
        if (output.full()) {
            throw ScannerFailureException.of(label, "It filled its output directory — " + capacity + " bytes, "
                    + ContainerRunner.OUTPUT_INODES + " files — so a write was refused and its report is not believed. "
                    + PluginManifest.OUTPUT + " holds the report and whatever the plugin writes beside it, never more "
                    + "than a scanner may hand back.");
        }
        if (result.exitCode() == FILE_TOO_LARGE_EXIT && !manifest.exitCodes().contains(result.exitCode())) {
            throw ScannerFailureException.of(label, "It was stopped for writing a file larger than " + capacity
                    + " bytes, the most any file of a plugin may weigh (exit " + FILE_TOO_LARGE_EXIT + ", SIGXFSZ).");
        }
        if (!manifest.exitCodes().contains(result.exitCode())) {
            throw ScannerFailureException.exited(label, result.exitCode(), result.stderr());
        }

        byte[] document = switch (output.file()) {
            case ContainerRunner.OutputFile.Read read -> read.bytes();
            case ContainerRunner.OutputFile.Missing missing -> throw ScannerFailureException.of(label,
                    "The plugin exited without writing its report to " + PluginManifest.OUTPUT + "/" + manifest.output() + ".");
            case ContainerRunner.OutputFile.NotRegular notRegular -> throw ScannerFailureException.of(label,
                    "Its report is not a regular file; a link or a device is not read.");
            case ContainerRunner.OutputFile.TooLarge tooLarge -> throw ScannerFailureException.of(label,
                    "Its report is larger than the " + runner.outputBytes() + " bytes a scanner may hand back.");
        };
        SarifReport report;
        try {
            report = SarifReport.read(document, runner.outputBytes(), List.of(PluginManifest.SOURCE));
        } catch (InvalidSarifException refused) {
            throw ScannerFailureException.of(label, "The plugin's report was refused: " + refused.getMessage());
        }
        return findings(report, label);
    }

    /**
     * The report as findings, or empty when it says it analysed nothing.
     *
     * <p>Every run must have succeeded and computed results: one run that failed among three that did
     * would otherwise hand back the other two's findings as the complete list — the merged-secrets
     * defect of decision 0007, in SARIF.
     */
    static Optional<PluginReport> findings(SarifReport report, String label) {
        if (report.runs().isEmpty()) {
            return Optional.empty();
        }
        List<SarifFinding> all = new ArrayList<>();
        for (SarifReport.Run run : report.runs()) {
            if (!run.successful()) {
                throw ScannerFailureException.of(label, "The plugin's report says its run \"" + run.toolName()
                        + "\" did not execute successfully.");
            }
            if (run.results().isEmpty()) {
                return Optional.empty();
            }
            all.addAll(run.results().get());
        }
        SarifReport.Run first = report.runs().getFirst();
        return Optional.of(new PluginReport(first.toolName(), first.toolVersion(), List.copyOf(all)));
    }
}

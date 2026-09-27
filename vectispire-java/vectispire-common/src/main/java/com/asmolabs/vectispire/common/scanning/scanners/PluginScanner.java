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
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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
 *   <li><b>One writable directory</b>, empty, at {@value PluginManifest#OUTPUT}, created for this
 *       run and deleted with the workspace. The report is read from there, not from stdout: a
 *       plugin can log what it likes without corrupting its SARIF.
 *   <li><b>As the workspace's owner, never root</b> — the Grype lesson: what root writes into a mount
 *       is root's on the host, and the unprivileged process cannot delete it afterwards. A host that
 *       reports no owner cannot run a plugin at all, rather than run it as root.
 *   <li><b>The network only when the manifest asks</b>, with the justification the governor wrote.
 *   <li><b>A timeout no longer than the scanners'</b>; the memory, process and CPU ceilings are the
 *       scanner limits', unchanged.
 * </ul>
 *
 * <p><b>The report is read like anything else a stranger wrote.</b> Not through a link (a plugin
 * could leave {@code results.sarif -> /etc/shadow} for this process to read), only a regular file,
 * and only up to the output ceiling, enforced while reading. Then {@link SarifReport}'s guards.
 *
 * <p><b>Returns empty, never an empty list, when the plugin did not analyse</b> (decision 0007): a
 * report with no run, or a run that says it computed no results. A failure it can explain — an
 * undeclared exit code, no report, a report refused, a run that says it failed — is thrown, and
 * the runner records the reason.
 */
public final class PluginScanner {

    /** Where each plugin's output directory is created, beside — never inside — the analysed tree. */
    static final String OUTPUT_SUBDIR = "plugins";

    private final ContainerRunner runner;
    private final String registryMirror;

    /**
     * @param registryMirror the internal registry plugin images are pulled from, or blank for their
     *     own — see {@link ImageDigest#relocate}
     */
    public PluginScanner(ContainerRunner runner, String registryMirror) {
        this.runner = runner;
        this.registryMirror = registryMirror == null || registryMirror.isBlank()
                ? null
                : ImageDigest.requireMirror(registryMirror);
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
        Path output = outputDirectory(workspace, manifest, label);
        String owner = ContainerRun.ownerOf(output).orElseThrow(() -> ScannerFailureException.of(label,
                "This host reports no owner for the workspace, so the plugin cannot run as an unprivileged user; "
                        + "it is not run as root instead."));

        ContainerRun run = ContainerRun.of(
                        ImageDigest.relocate(manifest.image(), registryMirror),
                        manifest.command(PluginManifest.SOURCE, PluginManifest.OUTPUT + "/" + manifest.output()),
                        List.of(
                                ContainerRun.Mount.readOnly(analysedRoot.toString(), PluginManifest.SOURCE),
                                ContainerRun.Mount.writable(output.toString(), PluginManifest.OUTPUT)),
                        label)
                .runningAs(owner);
        if (manifest.network()) {
            // The governor's declared exception, justified in the manifest and in the audit log.
            run = run.withNetwork();
        }
        if (manifest.timeoutSeconds() != null) {
            run = run.withTimeout(Duration.ofSeconds(manifest.timeoutSeconds()));
        }

        ContainerRunner.ContainerResult result = runner.run(run);
        if (!manifest.exitCodes().contains(result.exitCode())) {
            throw ScannerFailureException.exited(label, result.exitCode(), result.stderr());
        }

        byte[] document = readReport(output.resolve(manifest.output()), runner.outputBytes(), manifest, label);
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

    private static Path outputDirectory(Workspace workspace, PluginManifest manifest, String label) {
        Path output = workspace.root().resolve(OUTPUT_SUBDIR).resolve(manifest.id());
        try {
            Files.createDirectories(output.getParent());
            // `createDirectory`, not `createDirectories`: it fails if the directory exists, so a
            // report left there by anything else cannot be read as this run's.
            Files.createDirectory(output);
        } catch (IOException unwritable) {
            throw ScannerFailureException.of(label, "Its output directory could not be created: " + unwritable.getMessage());
        }
        return output;
    }

    /** The report's bytes: a regular file, not through a link, and no more than the ceiling. */
    private static byte[] readReport(Path file, long ceiling, PluginManifest manifest, String label) {
        BasicFileAttributes attributes;
        try {
            attributes = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException absent) {
            throw ScannerFailureException.of(label, "The plugin exited without writing its report to "
                    + PluginManifest.OUTPUT + "/" + manifest.output() + ".");
        } catch (IOException unreadable) {
            throw ScannerFailureException.of(label, "Its report could not be read: " + unreadable.getMessage());
        }
        if (!attributes.isRegularFile() || attributes.isSymbolicLink()) {
            throw ScannerFailureException.of(label, "Its report is not a regular file; a link or a device is not read.");
        }
        if (attributes.size() > ceiling) {
            throw ScannerFailureException.of(label, "Its report is larger than the " + ceiling + " bytes a scanner may hand back.");
        }
        try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            // Bounded while reading too: the file could grow between the check and the read.
            byte[] bytes = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, ceiling + 1));
            if (bytes.length > ceiling) {
                throw ScannerFailureException.of(label, "Its report is larger than the " + ceiling + " bytes a scanner may hand back.");
            }
            return bytes;
        } catch (IOException unreadable) {
            throw ScannerFailureException.of(label, "Its report could not be read: " + unreadable.getMessage());
        }
    }
}

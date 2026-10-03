package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.plugins.ImageDigest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.PluginRefusedException;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Running a report plugin (decision 0035 §2): a container image that reads a project's export and writes one
 * document — in 0017's closed shape, through the same {@link ContainerRunner}, tightened where a report differs
 * from a check.
 *
 * <p><b>What it shares with {@link PluginScanner}, as code</b>: {@link ContainerRun#of}'s shape — no capability,
 * {@code no-new-privileges}, a read-only root, {@code noexec} scratch, the scanner limits' memory, process and
 * CPU ceilings, removed in a {@code finally}; the signer checked by the pinned cosign before the pull ({@link
 * ImageSignatureVerifier}), with the control plane's own Docker configuration for a private registry (0017
 * §9.2); the bounded output kept by a holder ({@link ContainerRun.BoundedOutput}); the mirror
 * ({@link ImageDigest#relocate}); never root.
 *
 * <p><b>What is tightened</b>, each because the input is the most aggregated confidential document the
 * platform builds and the output leaves under its key:
 *
 * <ul>
 *   <li><b>No network, ever</b> — the manifest has no field to ask for it, and nothing here could grant it;
 *   <li><b>The signer is required, with no waiver and no executor setting</b>: a manifest without one is
 *       refused here even though the registry refuses it first, since a row written another way must not be
 *       the one that runs unsigned;
 *   <li><b>One input, read-only, holding {@code export.json} alone</b>: a directory of its own in the run's
 *       workspace, bind-mounted read-only at {@value ReportPluginManifest#INPUT} — the bind the scanners already
 *       go through the socket proxy with, so the proxy's filter needs nothing new. Written only once the
 *       signer is verified: an image nobody vouched for is never handed the project;
 *   <li><b>One output, bounded by the manifest</b> — {@code max_output_bytes}, sixteen inodes;
 *   <li><b>The manifest's timeout</b>, ten seconds to five minutes, and <b>exit code 0 or failed</b>.
 * </ul>
 *
 * <p><b>The output is not checked here.</b> Its bytes come back as the plugin wrote them, read as a regular
 * file up to the ceiling; checking them against the declared type ({@code ReportOutputCheck}), and signing
 * them, is the caller's next step, and nothing is served that has not passed both.
 */
public final class ReportPluginRenderer {

    /** The file the plugin reads, alone in its directory. */
    public static final String EXPORT_FILE = "export.json";

    /** A renderer writes one file: room for it, its directory and a few temporary ones (0035 §2). */
    public static final int OUTPUT_INODES = 16;

    /** Where the run's workspace keeps the signer's key and the registry login, beside — never inside — the input. */
    static final String TRUST_SUBDIR = "trust";

    static final String INPUT_SUBDIR = "input";

    /** A process killed by {@code SIGXFSZ}: it wrote a file past the directory's ceiling. */
    static final int FILE_TOO_LARGE_EXIT = PluginScanner.FILE_TOO_LARGE_EXIT;

    /** How much of the plugin's error stream a failure quotes. */
    private static final int QUOTED = 2000;

    /**
     * What came of a run. Never an exception for something the plugin or its provenance did: the caller records
     * each as a state with its reason, and only a fault of the caller's own escapes.
     */
    public sealed interface Outcome {

        /**
         * Whether the plugin's container may have read the export — false for every refusal, which happens
         * before the export is written, and for a failure before the container started.
         */
        boolean exportHandedOver();

        /** The plugin exited {@code 0} and wrote its file, read back as written — unchecked. */
        record Produced(byte[] output) implements Outcome {
            @Override
            public boolean exportHandedOver() {
                return true;
            }
        }

        /** Not started: no verified signer. */
        record Refused(ReportRunReason reason, String detail) implements Outcome {
            public Refused {
                if (reason.state() != ReportRunState.REFUSED) {
                    throw new IllegalArgumentException(reason + " is not a refusal.");
                }
            }

            @Override
            public boolean exportHandedOver() {
                return false;
            }
        }

        /** Started, or about to be, and went wrong. */
        record Failed(ReportRunReason reason, String detail, boolean exportHandedOver) implements Outcome {
            public Failed {
                if (reason.state() != ReportRunState.FAILED) {
                    throw new IllegalArgumentException(reason + " is not a failure.");
                }
            }
        }
    }

    private final ContainerRunner runner;
    private final String registryMirror;
    private final ImageSignatureVerifier verifier;
    private final Function<Path, Optional<String>> owners;

    /**
     * @param registryMirror the internal registry plugin images are pulled from, or blank for their own — the
     *     scanner plugins' setting ({@code VECTISPIRE_PLUGIN_REGISTRY}), which must then carry the signatures too
     */
    public ReportPluginRenderer(ContainerRunner runner, String registryMirror) {
        this(runner, registryMirror, ContainerRun::ownerOf);
    }

    /** @param owners how a directory's {@code uid:gid} is read — replaceable for the reason {@link PluginScanner}'s is */
    public ReportPluginRenderer(ContainerRunner runner, String registryMirror, Function<Path, Optional<String>> owners) {
        this.runner = runner;
        this.registryMirror = registryMirror == null || registryMirror.isBlank()
                ? null
                : ImageDigest.requireMirror(registryMirror);
        this.verifier = new ImageSignatureVerifier(runner);
        this.owners = owners;
    }

    /**
     * Renders {@code export} with the plugin {@code manifest} describes.
     *
     * @param manifest validated, and approved by whoever calls this — the renderer checks provenance, not
     *     governance
     */
    public Outcome render(ReportPluginManifest manifest, byte[] export) {
        String label = "report plugin " + manifest.id();
        if (manifest.signature() == null) {
            return new Outcome.Refused(ReportRunReason.UNSIGNED, "Its manifest declares no signer. A report plugin "
                    + "always needs one, with no waiver: the platform signs what it produces. It was not run.");
        }
        return Workspace.withWorkspace(workspace -> {
            Optional<String> owner = owners.apply(workspace.root());
            if (owner.isEmpty()) {
                return new Outcome.Failed(ReportRunReason.EXECUTOR_ERROR, "This host reports no owner for the run's "
                        + "directory, so the plugin cannot run as an unprivileged user; it is not run as root instead.",
                        false);
            }
            if (owner.get().startsWith("0:")) {
                return new Outcome.Failed(ReportRunReason.EXECUTOR_ERROR, "Vectispire runs as root here, so the run's "
                        + "directory is root's and the plugin would run as root; it is not run. Run Vectispire as an "
                        + "unprivileged user, as its images do (1000:1000).", false);
            }
            return render(manifest, export, workspace.root(), owner.get(), label);
        });
    }

    private Outcome render(ReportPluginManifest manifest, byte[] export, Path root, String owner, String label) {
        String image = ImageDigest.relocate(manifest.image(), registryMirror);
        try {
            // Before the pull, and before the export is written anywhere a container could read it.
            verifier.verify(image, manifest.signature(), root.resolve(TRUST_SUBDIR), owner, label,
                    ImageDigest.relocate(ImageSignatureVerifier.COSIGN, registryMirror));
        } catch (PluginRefusedException refused) {
            ReportRunReason reason = switch (refused.refusal()) {
                case UNSIGNED -> ReportRunReason.UNSIGNED;
                case SIGNATURE_UNVERIFIED -> ReportRunReason.SIGNATURE_UNVERIFIED;
                case REGISTRY_AUTHENTICATION_REQUIRED -> ReportRunReason.REGISTRY_AUTHENTICATION_REQUIRED;
            };
            return new Outcome.Refused(reason, refused.getMessage());
        } catch (ScannerFailureException unchecked) {
            // The verifier did not run: it said nothing about the image, which is not a refusal of it.
            return new Outcome.Failed(ReportRunReason.EXECUTOR_ERROR, unchecked.getMessage(), false);
        }

        Path input;
        try {
            input = writeInput(root, export);
        } catch (IOException unwritable) {
            return new Outcome.Failed(ReportRunReason.EXECUTOR_ERROR, "The export could not be handed to the plugin: "
                    + unwritable.getMessage(), false);
        }

        long ceiling = manifest.maxOutputBytes();
        ContainerRun run = ContainerRun.of(
                        image,
                        manifest.command(ReportPluginManifest.INPUT + "/" + EXPORT_FILE,
                                ReportPluginManifest.OUTPUT + "/" + manifest.output()),
                        List.of(ContainerRun.Mount.readOnly(input.toString(), ReportPluginManifest.INPUT)),
                        label)
                .runningAs(owner)
                .withBoundedOutput(new ContainerRun.BoundedOutput(ReportPluginManifest.OUTPUT, ceiling,
                        ImageDigest.relocate(PluginScanner.OUTPUT_HOLDER, registryMirror), manifest.output(), OUTPUT_INODES))
                .withTimeout(Duration.ofSeconds(manifest.timeoutSeconds()));

        ContainerRunner.ContainerResult result;
        try {
            result = runner.run(run);
        } catch (ScannerFailureException.TimedOut timedOut) {
            return new Outcome.Failed(ReportRunReason.TIMEOUT, "It ran past its " + manifest.timeoutSeconds()
                    + " seconds and was stopped.", true);
        } catch (ScannerFailureException failed) {
            // The pull, the daemon, the holder: whether the plugin started is unknown, so the export may have
            // been read — the audit log says so rather than the opposite.
            return new Outcome.Failed(ReportRunReason.EXECUTOR_ERROR, failed.getMessage(), true);
        }

        Optional<ContainerRunner.CollectedOutput> collected = result.output();
        if (collected.isEmpty()) {
            return new Outcome.Failed(ReportRunReason.EXECUTOR_ERROR, "Its output directory was not read back.", true);
        }
        ContainerRunner.CollectedOutput output = collected.get();
        // Before the exit code: a plugin refused a write usually exits on an error, and the directory being full
        // is the explanation its own words would only hint at.
        if (output.full() || result.exitCode() == FILE_TOO_LARGE_EXIT) {
            return new Outcome.Failed(ReportRunReason.OUTPUT_FULL, "It filled its output directory — " + ceiling
                    + " bytes (max_output_bytes), " + OUTPUT_INODES + " files — so a write was refused, and what could "
                    + "not be written is not in the document.", true);
        }
        if (result.exitCode() != 0) {
            String said = result.stderr() == null ? "" : result.stderr().strip();
            return new Outcome.Failed(ReportRunReason.EXIT_CODE, "It exited with " + result.exitCode() + ". "
                    + (said.length() <= QUOTED ? said : said.substring(0, QUOTED)), true);
        }
        return switch (output.file()) {
            case ContainerRunner.OutputFile.Read read -> new Outcome.Produced(read.bytes());
            case ContainerRunner.OutputFile.Missing missing -> new Outcome.Failed(ReportRunReason.OUTPUT_MISSING,
                    "It exited without writing " + ReportPluginManifest.OUTPUT + "/" + manifest.output() + ".", true);
            case ContainerRunner.OutputFile.NotRegular notRegular -> new Outcome.Failed(
                    ReportRunReason.OUTPUT_NOT_REGULAR, "Its output is not a regular file; a link or a device is not "
                            + "read.", true);
            case ContainerRunner.OutputFile.TooLarge tooLarge -> new Outcome.Failed(ReportRunReason.OUTPUT_FULL,
                    "Its output is larger than the " + ceiling + " bytes its manifest allows.", true);
        };
    }

    /**
     * The input directory, holding {@value #EXPORT_FILE} alone — the file readable by its owner only, the
     * directory writable by its owner so that the workspace's removal can delete the file. What keeps the plugin
     * from writing there is the read-only mount, not the mode: it runs as that owner.
     */
    private static Path writeInput(Path root, byte[] export) throws IOException {
        Path input = Files.createDirectory(root.resolve(INPUT_SUBDIR),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path file = input.resolve(EXPORT_FILE);
        Files.write(file, export);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("r--------"));
        return input;
    }
}

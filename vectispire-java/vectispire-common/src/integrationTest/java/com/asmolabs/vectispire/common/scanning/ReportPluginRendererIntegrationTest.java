package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportMediaType;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputCheck;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPackage;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportProvenance;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.scanning.scanners.ImageSignatureVerifier;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.dockerjava.api.DockerClient;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A report plugin run end to end through the real {@link ContainerRunner} (decision 0035 §2): the signer
 * verified by the pinned cosign before the pull, the export handed over read-only and alone, the network
 * absent, the output bounded by the manifest, the timeout and the exit code enforced.
 *
 * <p><b>The plugin is a signed public image, its program in its arguments.</b> distroless {@code
 * debug-nonroot} is signed keyless by Google's distroless identity, and its entrypoint is a busybox shell, so a
 * renderer — and every probe below — is a script handed as the manifest's arguments, {@code $1} the export and
 * {@code $2} the output. An image built here and signed with a throwaway key would need a registry the daemon
 * pulls from and the verifier's container reads over TLS, which {@link PluginSignatureIntegrationTest} explains
 * this suite does not build; a signature that verifies is what matters, and this one does. Each probe that must
 * hold exits on a code of its own when it does not, so a failure names the guarantee that broke.
 *
 * <p>Needs the internet, like the rest of the campaign — the image and Sigstore's trust root. <b>No skip
 * guard.</b>
 */
@DisplayName("a report plugin, run end to end in the closed shape")
class ReportPluginRendererIntegrationTest {

    /** distroless static, debian 12, {@code debug-nonroot}, by index digest — {@link PluginSignatureIntegrationTest}'s. */
    private static final String SIGNED =
            "gcr.io/distroless/static-debian12@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee";

    private static final PluginSignature DISTROLESS = new PluginSignature(
            "keyless@distroless.iam.gserviceaccount.com", "https://accounts.google.com", null);

    private static final long CEILING = 1024 * 1024;

    private static final byte[] EXPORT = "{\"schema\":\"vectispire-project-export\",\"schema_version\":\"1.0\"}"
            .getBytes(StandardCharsets.UTF_8);

    private static final ContainerRunner RUNNER = new ContainerRunner();
    private static final ObjectMapper JSON = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final DockerClient DOCKER = DockerClients.local();
    private static final ReportPluginRenderer RENDERER = new ReportPluginRenderer(RUNNER, null);

    /**
     * The probes a well-behaved renderer passes, each failing on its own code: the network (7), a write into
     * the input (8), anything but the export beside it (9). Then the export's digest is the document.
     */
    private static final String RENDERER_SCRIPT = String.join("\n",
            "if wget -q -T 5 -O /dev/null http://1.1.1.1/ 2>/dev/null; then echo 'network reached' >&2; exit 7; fi",
            "if touch \"$(dirname \"$1\")/written\" 2>/dev/null; then echo 'input writable' >&2; exit 8; fi",
            "if [ \"$(ls -A \"$(dirname \"$1\")\")\" != 'export.json' ]; then ls -A \"$(dirname \"$1\")\" >&2; exit 9; fi",
            "sha256sum \"$1\" | cut -d ' ' -f 1 > \"$2\"");

    @BeforeAll
    static void daemonIsReachable() {
        assertThat(RUNNER.isAvailable())
                .as("this suite needs a Docker daemon; it does not skip itself when there is none")
                .isTrue();
    }

    private static ReportPluginManifest plugin(String script, int timeoutSeconds, PluginSignature signer) {
        return new ReportPluginManifest("probe", "Probe", SIGNED, 1,
                List.of("-c", script, "probe", ReportPluginManifest.INPUT_PLACEHOLDER,
                        ReportPluginManifest.OUTPUT_PLACEHOLDER),
                "probe.txt", ReportMediaType.TEXT, CEILING, timeoutSeconds, signer).validated();
    }

    private static ReportPluginManifest plugin(String script) {
        return plugin(script, 60, DISTROLESS);
    }

    @Test
    @DisplayName("produced: verified, no network, the export alone and read-only, its file read back as written")
    void produced() {
        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin(RENDERER_SCRIPT), EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Produced.class, produced ->
                assertThat(new String(produced.output(), StandardCharsets.US_ASCII).strip())
                        .as("the plugin read the export it was given, byte for byte")
                        .isEqualTo(Digests.sha256Hex(EXPORT)));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("a connection attempt finds no network: the container has none to reach")
    void noNetwork() {
        // Without the network the probe's wget fails at once; with it, the probe exits 7 and the run fails.
        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin(
                "wget -T 5 -O /dev/null http://1.1.1.1/ 2>&1 | head -c 400 > \"$2\"; "
                        + "echo \"routes=$(tail -n +2 /proc/net/route | wc -l)\" >> \"$2\""),
                EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Produced.class, produced -> {
            String said = new String(produced.output(), StandardCharsets.UTF_8);
            assertThat(said).containsIgnoringCase("unreachable");
            assertThat(said).as("no route at all, not even a default one").contains("routes=0");
        });
    }

    @Test
    @DisplayName("an output over max_output_bytes fills the directory and fails the run, never read short")
    void outputBounded() {
        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin(
                "head -c " + (2 * CEILING) + " /dev/zero > \"$2\"; exit 0"), EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Failed.class, failed -> {
            assertThat(failed.reason()).isEqualTo(ReportRunReason.OUTPUT_FULL);
            assertThat(failed.detail()).contains(String.valueOf(CEILING));
        });
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("sixteen files and no more: a renderer creating twenty fills its directory")
    void sixteenInodes() {
        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin(
                "cd \"$(dirname \"$2\")\" && seq 1 20 | xargs touch 2>/dev/null; echo done > \"$2\"; exit 0"), EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Failed.class, failed ->
                assertThat(failed.reason()).isEqualTo(ReportRunReason.OUTPUT_FULL));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("the manifest's timeout stops the plugin, and the run fails for it")
    void timeout() {
        long started = System.nanoTime();
        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin("sleep 120; echo late > \"$2\"",
                ReportPluginManifest.MIN_TIMEOUT_SECONDS, DISTROLESS), EXPORT);
        long seconds = (System.nanoTime() - started) / 1_000_000_000L;

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Failed.class, failed -> {
            assertThat(failed.reason()).isEqualTo(ReportRunReason.TIMEOUT);
            assertThat(failed.exportHandedOver()).isTrue();
        });
        assertThat(seconds).as("stopped at its ten seconds, not left to its two minutes").isLessThan(100);
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("an exit code other than 0 fails the run, whatever it wrote, with its own words")
    void exitCode() {
        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin(
                "echo partial > \"$2\"; echo 'template missing' >&2; exit 3"), EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Failed.class, failed -> {
            assertThat(failed.reason()).isEqualTo(ReportRunReason.EXIT_CODE);
            assertThat(failed.detail()).contains("exited with 3").contains("template missing");
        });
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("another signer is refused before anything starts: the export is never handed over")
    void anotherSigner() {
        PluginSignature impostor = new PluginSignature(
                "https://github.com/acme/reports/.github/workflows/release.yml@refs/tags/v1",
                "https://token.actions.githubusercontent.com", null);

        ReportPluginRenderer.Outcome outcome = RENDERER.render(plugin(RENDERER_SCRIPT, 60, impostor), EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Refused.class, refused -> {
            assertThat(refused.reason()).isEqualTo(ReportRunReason.SIGNATURE_UNVERIFIED);
            assertThat(refused.detail()).contains("was not run").contains("keyless@distroless.iam.gserviceaccount.com");
            assertThat(refused.exportHandedOver()).isFalse();
        });
        assertNothingLeftBehind();
    }

    /**
     * The rest of a produced run, on the file a real container wrote (decision 0035 §3): checked against its
     * declared type, signed and packaged with its provenance as the control plane does ({@link
     * ReportPackage#sign}), then verified by the pinned cosign — the commands the guide gives a recipient — from
     * the package's own entries. A byte changed in the file and both commands refuse it. The download that hands
     * the package over is the HTTP suite's ({@code ReportRunsRoutesTest}): this suite has no control plane.
     */
    @Test
    @DisplayName("produced, checked, signed and packaged: cosign verifies the file and its provenance from the package")
    void packageVerifiesWithCosign() throws IOException {
        ReportPluginManifest manifest = new ReportPluginManifest("probe", "Probe", SIGNED, 1,
                List.of("-c", "printf 'export_sha256\\n%s\\n' \"$(sha256sum \"$1\" | cut -d ' ' -f 1)\" > \"$2\"",
                        "probe", ReportPluginManifest.INPUT_PLACEHOLDER, ReportPluginManifest.OUTPUT_PLACEHOLDER),
                "probe.csv", ReportMediaType.CSV, CEILING, 60, DISTROLESS).validated();
        ReportPluginRenderer.Outcome outcome = RENDERER.render(manifest, EXPORT);
        assertThat(outcome).isInstanceOf(ReportPluginRenderer.Outcome.Produced.class);
        byte[] output = ((ReportPluginRenderer.Outcome.Produced) outcome).output();
        assertThat(new String(output, StandardCharsets.UTF_8)).isEqualTo("export_sha256\n" + Digests.sha256Hex(EXPORT) + "\n");
        assertThat(ReportOutputCheck.check(manifest.mediaType(), output, CEILING))
                .isInstanceOf(ReportOutputCheck.Verdict.Accepted.class);

        KeyPair key = CosignSigner.generateKeyPair();
        String keyId = CosignSigner.computeKeyId(key.getPublic());
        Instant now = Instant.now();
        ReportProvenance provenance = ReportProvenance.of(new ReportProvenance.Predicate(
                new ReportProvenance.Run(7, now, now, now, now),
                new ReportProvenance.Project(12, "Checkout"),
                new ReportProvenance.Requester(3, "Ada Lovelace"),
                new ReportProvenance.Plugin("probe", "c".repeat(64), SIGNED, SIGNED.substring(SIGNED.indexOf('@') + 1),
                        new ReportProvenance.Signer(DISTROLESS.identity(), DISTROLESS.issuer(), null)),
                new ReportProvenance.Export("vectispire-project-export", "1.0", "export-1", Digests.sha256Hex(EXPORT),
                        EXPORT.length),
                new ReportProvenance.Output("probe.csv", manifest.mediaType().wireName(), Digests.sha256Hex(output),
                        output.length),
                new ReportProvenance.Producer("test", keyId),
                ReportProvenance.CLAIM));
        ReportPackage.Packed packed = ReportPackage.sign("probe.csv", output, provenance,
                (payloadType, payload) -> CosignSigner.wrapAndSignDsse(payloadType, payload, key.getPrivate(), keyId),
                JSON);

        Path unpacked = Files.createTempDirectory("report-package");
        try {
            try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(packed.content()))) {
                ZipEntry entry;
                while ((entry = zip.getNextEntry()) != null) {
                    Files.write(unpacked.resolve(entry.getName()), zip.readAllBytes());
                }
            }
            Files.writeString(unpacked.resolve("vectispire-signing-key.pub"), CosignSigner.toPem(key.getPublic()));
            Files.write(unpacked.resolve("tampered.csv"), (new String(output, StandardCharsets.UTF_8) + "1\n")
                    .getBytes(StandardCharsets.UTF_8));

            try (var files = Files.list(unpacked)) {
                assertThat(files.map(path -> path.getFileName().toString()))
                        .as("the file is never signed raw by the key VEX and CSAF are signed with")
                        .containsExactlyInAnyOrder("probe.csv", "provenance.json", "vectispire-signing-key.pub",
                                "tampered.csv");
            }
            assertThat(cosign(unpacked, "verify-blob-attestation", "--type=" + ReportProvenance.PREDICATE_TYPE,
                    "--signature=/package/provenance.json", "/package/probe.csv"))
                    .as("the provenance's envelope, and its subject the file's digest").isZero();
            assertThat(cosign(unpacked, "verify-blob-attestation", "--type=" + ReportProvenance.PREDICATE_TYPE,
                    "--signature=/package/provenance.json", "/package/tampered.csv"))
                    .as("the statement names another file").isNotZero();
        } finally {
            try (var files = Files.walk(unpacked)) {
                files.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
            }
        }
    }

    @Test
    @DisplayName("a page written as a CSV by a real container is refused by the check: nothing to sign")
    void disguisedOutputRefused() {
        ReportPluginManifest manifest = new ReportPluginManifest("probe", "Probe", SIGNED, 1,
                List.of("-c", "echo '<html><script>fetch(\"/api/v1/users\")</script></html>' > \"$2\"", "probe",
                        ReportPluginManifest.INPUT_PLACEHOLDER, ReportPluginManifest.OUTPUT_PLACEHOLDER),
                "probe.csv", ReportMediaType.CSV, CEILING, 60, DISTROLESS).validated();
        ReportPluginRenderer.Outcome outcome = RENDERER.render(manifest, EXPORT);

        assertThat(outcome).isInstanceOfSatisfying(ReportPluginRenderer.Outcome.Produced.class, produced ->
                assertThat(ReportOutputCheck.check(manifest.mediaType(), produced.output(), CEILING))
                        .isInstanceOfSatisfying(ReportOutputCheck.Verdict.Refused.class,
                                refused -> assertThat(refused.why()).contains("HTML")));
        assertNothingLeftBehind();
    }

    /** cosign at its pinned digest, against the key in {@code directory}, with no network: what a recipient runs. */
    private static int cosign(Path directory, String command, String... arguments) {
        List<String> argv = new ArrayList<>(List.of(command, "--key=/package/vectispire-signing-key.pub",
                "--insecure-ignore-tlog=true"));
        argv.addAll(List.of(arguments));
        ContainerRunner.ContainerResult result = RUNNER.run(ContainerRun.of(ImageSignatureVerifier.COSIGN, argv,
                        List.of(ContainerRun.Mount.readOnly(directory.toString(), "/package")), "report package check")
                .runningAsOwnerOf(directory));
        return result.exitCode();
    }

    /** Neither the plugin, nor its holder, nor the holder's volume survives the run. */
    private static void assertNothingLeftBehind() {
        assertThat(DOCKER.listContainersCmd().withShowAll(true)
                        .withLabelFilter(Map.of(ContainerRunner.SCANNER_LABEL, "report plugin probe")).exec())
                .as("the plugin's container is removed")
                .isEmpty();
        assertThat(DOCKER.listContainersCmd().withShowAll(true)
                        .withLabelFilter(Map.of(ContainerRunner.SCANNER_LABEL, "report plugin probe (output)")).exec())
                .as("the holder is removed")
                .isEmpty();
        var volumes = DOCKER.listVolumesCmd()
                .withFilter("label", List.of(ContainerRunner.SCANNER_LABEL + "=report plugin probe (output)"))
                .exec()
                .getVolumes();
        assertThat(volumes == null ? List.of() : volumes).as("and its volume with it").isEmpty();
    }
}

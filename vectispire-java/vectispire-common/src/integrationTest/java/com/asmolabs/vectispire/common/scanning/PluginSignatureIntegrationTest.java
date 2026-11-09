package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.exception.NotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A plugin's declared signer, checked by the pinned cosign against a real registry.
 *
 * <p><b>Public images and Sigstore's public instance</b>, because they are the ones whose signers are
 * known and stable: distroless is signed keyless by {@code keyless@distroless.iam.gserviceaccount.com}
 * through Google's issuer, and its {@code debug} variants carry a busybox shell a plugin can be
 * written in. So this suite needs the internet — which it already did, for every image it pulls.
 *
 * <p>Key verification that <em>succeeds</em> needs an image signed with a key this suite holds, hence
 * a registry of its own that both the daemon and the verifier's container reach over TLS; that is
 * not built here, and was checked by hand (the report of the change says how). The key path is
 * exercised to its refusal: the key is mounted, read, and answers "no signatures found" for an image
 * nobody signed with it.
 *
 * <p><b>No skip guard</b>, as for the rest of this suite.
 */
@DisplayName("a plugin's signer, against a real registry")
class PluginSignatureIntegrationTest {

    /** distroless static, debian 12, {@code debug-nonroot}: a shell, signed keyless, by index digest. */
    private static final String SIGNED =
            "gcr.io/distroless/static-debian12@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee";

    /** The {@code debug} variant, used only to be refused: it must never reach this host. */
    private static final String REFUSED =
            "gcr.io/distroless/static-debian12@sha256:e60a053e6dd251ece065cc35e08c28f4ed55c559eeeb9102553bb09d5c0b0ad1";

    private static final PluginSignature DISTROLESS = new PluginSignature(
            "keyless@distroless.iam.gserviceaccount.com", "https://accounts.google.com", null);

    /** A P-256 key nobody signed anything with. */
    private static final String UNUSED_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhm3H+258usrgldBUFUFN9WFtNT21\n"
            + "IV1MQgw1S41uz9HTMzDeHNZ9+PsTOW6xznu1CIrVOSLBcsTdCfoM911hVg==\n"
            + "-----END PUBLIC KEY-----\n";

    private static final ContainerRunner RUNNER = new ContainerRunner();
    private static final DockerClient DOCKER = DockerClients.local();

    @BeforeAll
    static void daemonIsReachable() {
        assertThat(RUNNER.isAvailable())
                .as("this suite needs a Docker daemon; it does not skip itself when there is none")
                .isTrue();
    }

    private static PluginManifest plugin(String image, PluginSignature signature) {
        // distroless debug's entrypoint is its busybox shell: the arguments are the shell's.
        return new PluginManifest("probe", "Signed probe", image, Set.of(Language.PYTHON),
                List.of("-c", "echo '" + PluginScannerIntegrationTest.EMPTY_REPORT + "' > \"$2\"", "probe",
                        PluginManifest.SOURCE_PLACEHOLDER, PluginManifest.OUTPUT_PLACEHOLDER),
                "results.sarif", Set.of(0), false, null, 120, signature);
    }

    private static PluginStep run(PluginManifest manifest, PluginScanner.Settings settings) {
        return Workspace.withWorkspace(workspace -> {
            try {
                Files.createDirectories(workspace.source().resolve("app"));
                Files.writeString(workspace.source().resolve("app/a.py"), "print(1)");
                Path analysed = SourceFiles.within(workspace.source(), null);
                List<PluginStep> steps = new PluginSteps(new PluginScanner(RUNNER, settings), reference -> manifest)
                        .run(List.of(new PluginRef(manifest.id(), manifest.digest())), workspace, analysed);
                assertThat(steps).hasSize(1);
                return steps.getFirst();
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
    }

    @Test
    @DisplayName("an image signed by the declared keyless signer is verified, pulled and run")
    void keyless() {
        PluginStep step = run(plugin(SIGNED, DISTROLESS), PluginScanner.Settings.DEFAULT);

        assertThat(step).isInstanceOfSatisfying(PluginStep.Produced.class, produced -> {
            assertThat(produced.findings()).isEmpty();
            assertThat(produced.signature()).isEqualTo(PluginStep.Signature.VERIFIED);
        });
        PluginScannerIntegrationTest.assertNothingLeftBehind();
    }

    @Test
    @DisplayName("another signer is refused in cosign's words, and the image is never pulled")
    void anotherSigner() {
        forget(REFUSED);
        PluginSignature impostor = new PluginSignature(
                "https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v1",
                "https://token.actions.githubusercontent.com", null);

        PluginStep step = run(plugin(REFUSED, impostor), PluginScanner.Settings.DEFAULT);

        assertThat(step).isInstanceOfSatisfying(PluginStep.Refused.class, refused -> {
            assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.SIGNATURE_UNVERIFIED);
            assertThat(refused.reason()).contains("was not run").contains("keyless@distroless.iam.gserviceaccount.com");
        });
        assertThatThrownBy(() -> DOCKER.inspectImageCmd(REFUSED).exec())
                .as("verified before the pull: an image nobody verified is not even fetched")
                .isInstanceOf(NotFoundException.class);
        PluginScannerIntegrationTest.assertNothingLeftBehind();
    }

    @Test
    @DisplayName("a key the image was not signed with is refused: the key is read, and no signature matches it")
    void key() {
        forget(REFUSED);

        PluginStep step = run(plugin(REFUSED, new PluginSignature(null, null, UNUSED_KEY)), PluginScanner.Settings.DEFAULT);

        assertThat(step).isInstanceOfSatisfying(PluginStep.Refused.class, refused -> {
            assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.SIGNATURE_UNVERIFIED);
            assertThat(refused.reason()).contains("was not run").containsAnyOf("no signatures found", "no matching signatures");
        });
        assertThatThrownBy(() -> DOCKER.inspectImageCmd(REFUSED).exec()).isInstanceOf(NotFoundException.class);
    }

    @Test
    @DisplayName("the default executor refuses an unsigned plugin before anything starts")
    void required() {
        forget(REFUSED);

        PluginStep step = run(plugin(REFUSED, null), PluginScanner.Settings.DEFAULT);

        assertThat(step).isInstanceOfSatisfying(PluginStep.Refused.class, refused -> {
            assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.UNSIGNED);
            assertThat(refused.reason()).contains("VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED");
        });
        assertThatThrownBy(() -> DOCKER.inspectImageCmd(REFUSED).exec()).isInstanceOf(NotFoundException.class);
    }

    /** Removes an image a previous run may have pulled, so that "never pulled" is observable. */
    private static void forget(String image) {
        try {
            DOCKER.removeImageCmd(image).withForce(true).exec();
        } catch (NotFoundException absent) {
            // Already the state wanted.
        }
    }
}

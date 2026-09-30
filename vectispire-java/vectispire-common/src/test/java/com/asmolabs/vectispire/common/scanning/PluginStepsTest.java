package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.scanning.scanners.ImageSignatureVerifier;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

/**
 * A plugin's three states, decided without a clone and without a daemon: the container is a stub
 * that writes what the plugin would have written into a directory standing for its bounded output,
 * and answers what the runner would have read back from it. The verifier's run — cosign — is told
 * apart by its label and answers {@link #verification}.
 */
@DisplayName("the plugins of a scan")
class PluginStepsTest {

    private static final String DIGEST = "sha256:" + "d".repeat(64);

    static final String REPORT = """
            {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"acme-lint","version":"4.2.0"}},
             "results":[{"ruleId":"ACME001","level":"error","message":{"text":"eval() here"},
               "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/repo/source/app/a.py"},"region":{"startLine":3}}}]}]}]}
            """;

    @TempDir
    Path root;

    private Workspace workspace;
    private ContainerRunner containers;
    /** Not the build's own user: the CI runs as root, a developer does not, and both must pass. */
    private String owner = "1000:1000";
    private final AtomicReference<ContainerRun> launched = new AtomicReference<>();
    private final AtomicReference<ContainerRun> verified = new AtomicReference<>();
    /** What cosign answers: its exit code and its words. */
    private ContainerRunner.ContainerResult verification = new ContainerRunner.ContainerResult("[{}]", "Verified OK", 0);
    /** Whether the output directory is reported full, as the holder's {@code df} would say. */
    private boolean full;

    @BeforeEach
    void checkout() throws IOException {
        workspace = new Workspace(root, root.resolve(Workspace.SOURCE_SUBDIR), root.resolve(Workspace.RULES_SUBDIR));
        Files.createDirectories(workspace.source().resolve("app"));
        Files.writeString(workspace.source().resolve("app/a.py"), "eval(input())");
        containers = mock(ContainerRunner.class);
        when(containers.outputBytes()).thenReturn(ScannerLimits.DEFAULT_OUTPUT_BYTES);
    }

    static PluginManifest manifest(Set<Language> languages) {
        return new PluginManifest("acme-lint", "ACME", "registry.acme.internal/acme-lint@" + DIGEST, languages,
                List.of("--out", "{output}", "{source}"), "results.sarif", Set.of(0, 1), false, null, 120);
    }

    private static PluginRef ref(PluginManifest manifest) {
        return new PluginRef(manifest.id(), manifest.digest());
    }

    /** The container writes {@code content} as its report and exits on {@code code}. */
    private void plugin(int code, Consumer<Path> writes) {
        when(containers.run(any())).thenAnswer(invocation -> {
            ContainerRun run = invocation.getArgument(0);
            if (run.label().endsWith(" signature")) {
                verified.set(run);
                return verification;
            }
            launched.set(run);
            Path output = Files.createTempDirectory(root, "output");
            writes.accept(output);
            return new ContainerRunner.ContainerResult("", "the plugin's own complaint", code,
                    Optional.of(readBack(run.output(), output)));
        });
    }

    /** What the runner answers for a bounded output: the file as the archive would, the space as df would. */
    private ContainerRunner.CollectedOutput readBack(ContainerRun.BoundedOutput bounded, Path directory) throws IOException {
        Path file = directory.resolve(bounded.file());
        ContainerRunner.OutputFile read;
        if (!Files.exists(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            read = new ContainerRunner.OutputFile.Missing();
        } else if (!Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            read = new ContainerRunner.OutputFile.NotRegular();
        } else if (Files.size(file) > containers.outputBytes()) {
            read = new ContainerRunner.OutputFile.TooLarge(Files.size(file));
        } else {
            read = new ContainerRunner.OutputFile.Read(Files.readAllBytes(file));
        }
        return new ContainerRunner.CollectedOutput(bounded.bytes(), full ? 0 : 1 << 20, full ? 0 : 100, read);
    }

    private static Consumer<Path> writing(String report) {
        return output -> {
            try {
                Files.writeString(output.resolve("results.sarif"), report);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
    }

    private List<PluginStep> run(PluginManifest manifest) {
        return run(manifest, reference -> manifest, null);
    }

    private PluginScanner scanner(String mirror) {
        return scannerWith(new PluginScanner.Settings(mirror, false));
    }

    private PluginScanner scannerWith(PluginScanner.Settings settings) {
        return new PluginScanner(containers, settings, directory -> Optional.ofNullable(owner));
    }

    private List<PluginStep> run(PluginManifest manifest, PluginProvider provider, String mirror) {
        return new PluginSteps(scanner(mirror), provider)
                .run(List.of(ref(manifest)), workspace, workspace.source());
    }

    @Nested
    @DisplayName("produced")
    class Produced {

        @Test
        @DisplayName("a plugin whose language is present runs, and its report becomes its findings")
        void produced() {
            plugin(0, writing(REPORT));

            List<PluginStep> steps = run(manifest(Set.of(Language.PYTHON)));

            assertThat(steps).containsExactly(new PluginStep.Produced("acme-lint", manifest(Set.of(Language.PYTHON)).digest(),
                    "acme-lint", "4.2.0", List.of(new SarifFinding("ACME001", Severity.HIGH, "app/a.py", 3, "eval() here")),
                    PluginStep.Signature.NOT_REQUIRED));
        }

        @Test
        @DisplayName("an empty report is a plugin that ran and found nothing — the one state that resolves")
        void empty() {
            plugin(0, writing("{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"acme-lint\"}},\"results\":[]}]}"));

            assertThat(run(manifest(Set.of(Language.PYTHON))))
                    .singleElement()
                    .isInstanceOfSatisfying(PluginStep.Produced.class, step -> assertThat(step.findings()).isEmpty());
        }

        @Test
        @DisplayName("runs in the closed shape: tree read-only, one bounded output, no network, not root, argv not shell")
        void confinement() throws IOException {
            plugin(1, writing(REPORT));

            run(manifest(Set.of(Language.PYTHON)));

            ContainerRun run = launched.get();
            assertThat(run.network()).isFalse();
            assertThat(run.asRoot()).isFalse();
            assertThat(run.user())
                    .as("the workspace owner, so what the plugin writes stays deletable and nothing runs as root")
                    .isEqualTo("1000:1000");
            assertThat(run.mounts())
                    .as("the tree alone, read-only: the output is no directory of the host")
                    .containsExactly(ContainerRun.Mount.readOnly(workspace.source().toString(), PluginManifest.SOURCE));
            assertThat(run.output())
                    .as("a directory that holds no more than the scanner output ceiling, kept by the pinned holder")
                    .isEqualTo(new ContainerRun.BoundedOutput(PluginManifest.OUTPUT, ScannerLimits.DEFAULT_OUTPUT_BYTES,
                            PluginScanner.OUTPUT_HOLDER, "results.sarif"));
            assertThat(run.mounts())
                    .as("never the workspace root: it holds the secrets report in the clear")
                    .noneMatch(mount -> mount.source().equals(root.toString()));
            assertThat(run.command()).containsExactly("--out", "/repo/output/results.sarif", "/repo/source");
            assertThat(run.timeout()).isEqualTo(Duration.ofSeconds(120));
            assertThat(run.image()).isEqualTo("registry.acme.internal/acme-lint@" + DIGEST);
        }

        @Test
        @DisplayName("the network is opened only for a plugin that declared it")
        void declaredNetwork() {
            plugin(0, writing(REPORT));
            PluginManifest networked = new PluginManifest("acme-lint", "ACME", "registry.acme.internal/acme-lint@" + DIGEST,
                    Set.of(Language.PYTHON), List.of(), "results.sarif", Set.of(0), true,
                    "fetches its rule database from the internal mirror", null);

            run(networked);

            assertThat(launched.get().network()).isTrue();
        }

        @Test
        @DisplayName("the image is pulled from the internal registry, by the same digest")
        void mirrored() {
            plugin(0, writing(REPORT));

            run(manifest(Set.of(Language.PYTHON)), reference -> manifest(Set.of(Language.PYTHON)), "mirror.internal:5000");

            assertThat(launched.get().image()).isEqualTo("mirror.internal:5000/acme-lint@" + DIGEST);
            assertThat(launched.get().output().holderImage())
                    .as("the holder comes through the mirror too, by the same digest")
                    .isEqualTo("mirror.internal:5000/library/" + PluginScanner.OUTPUT_HOLDER);
        }
    }

    @Nested
    @DisplayName("a declared signer")
    class Signer {

        private final PluginManifest keyless = signed(new PluginSignature(
                "https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v4.2.0",
                "https://token.actions.githubusercontent.com", null));

        private final PluginManifest keyed = signed(new PluginSignature(null, null, "-----BEGIN PUBLIC KEY-----\n"
                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhm3H+258usrgldBUFUFN9WFtNT21\n"
                + "IV1MQgw1S41uz9HTMzDeHNZ9+PsTOW6xznu1CIrVOSLBcsTdCfoM911hVg==\n"
                + "-----END PUBLIC KEY-----\n"));

        private PluginManifest signed(PluginSignature signature) {
            PluginManifest m = manifest(Set.of(Language.PYTHON));
            return new PluginManifest(m.id(), m.name(), m.image(), m.languages(), m.arguments(), m.output(), m.exitCodes(),
                    m.network(), m.networkJustification(), m.timeoutSeconds(), signature);
        }

        @Test
        @DisplayName("keyless: cosign checks the exact identity and issuer, with the network and no file of the target")
        void keyless() {
            plugin(0, writing(REPORT));

            assertThat(run(keyless)).singleElement().isInstanceOf(PluginStep.Produced.class);

            ContainerRun check = verified.get();
            assertThat(check.image()).isEqualTo(ImageSignatureVerifier.COSIGN);
            assertThat(check.command()).containsExactly("verify",
                    "--certificate-identity=https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v4.2.0",
                    "--certificate-oidc-issuer=https://token.actions.githubusercontent.com",
                    "registry.acme.internal/acme-lint@" + DIGEST);
            assertThat(check.network()).as("the signature is in the registry").isTrue();
            assertThat(check.mounts()).as("no tree, no workspace, no key: nothing of the target").isEmpty();
            assertThat(check.user()).isEqualTo("1000:1000");
            assertThat(check.asRoot()).isFalse();
        }

        @Test
        @DisplayName("key: the public key alone, mounted read-only; the transparency log is not consulted")
        void key() throws IOException {
            plugin(0, writing(REPORT));

            assertThat(run(keyed)).singleElement().isInstanceOf(PluginStep.Produced.class);

            ContainerRun check = verified.get();
            assertThat(check.command()).containsExactly("verify", "--key=/trust/cosign.pub", "--insecure-ignore-tlog=true",
                    "registry.acme.internal/acme-lint@" + DIGEST);
            assertThat(check.mounts()).singleElement().satisfies(mount -> {
                assertThat(mount.readOnly()).isTrue();
                assertThat(mount.target()).isEqualTo("/trust/cosign.pub");
                assertThat(Files.readString(Path.of(mount.source()))).isEqualTo(keyed.signature().publicKey());
                assertThat(Path.of(mount.source()).startsWith(workspace.source()))
                        .as("the key is kept outside the tree the plugin reads")
                        .isFalse();
            });
        }

        @Test
        @DisplayName("an image cosign does not verify is never run, and the plugin is refused in cosign's words")
        void refused() {
            verification = new ContainerRunner.ContainerResult("", "Error: no matching signatures", 1);
            plugin(0, writing(REPORT));

            List<PluginStep> steps = run(keyless);

            assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Refused.class, refused -> {
                assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.SIGNATURE_UNVERIFIED);
                assertThat(refused.reason()).contains("was not run").contains("no matching signatures");
            });
            assertThat(launched.get()).as("the plugin's container is never created").isNull();
        }

        @Test
        @DisplayName("a waiver lifts the duty to declare a signer, never the verification of one declared")
        void waiverDoesNotCoverADeclaredSigner() {
            verification = new ContainerRunner.ContainerResult("", "Error: no matching signatures", 1);
            plugin(0, writing(REPORT));

            List<PluginStep> steps = new PluginSteps(scannerWith(PluginScanner.Settings.DEFAULT), reference -> keyless)
                    .run(List.of(new PluginRef(keyless.id(), keyless.digest(), true)), workspace, workspace.source());

            assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Refused.class, refused ->
                    assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.SIGNATURE_UNVERIFIED));
            assertThat(launched.get()).isNull();
        }

        @Test
        @DisplayName("a verifier that could not run is never a pass: absent, it said nothing of the image")
        void verifierFailed() {
            when(containers.run(any())).thenAnswer(invocation -> {
                ContainerRun run = invocation.getArgument(0);
                if (run.label().endsWith(" signature")) {
                    throw ScannerFailureException.of(run.label(), "the verifier image could not be fetched");
                }
                launched.set(run);
                return new ContainerRunner.ContainerResult("", "", 0);
            });

            assertThat(run(keyless)).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                    assertThat(absent.reason()).contains("could not be checked").contains("could not be fetched"));
            assertThat(launched.get()).isNull();
        }

        @Test
        @DisplayName("through a mirror, cosign checks the image as it will be pulled, and comes from the mirror too")
        void mirrored() {
            plugin(0, writing(REPORT));

            run(keyless, reference -> keyless, "mirror.internal:5000");

            assertThat(verified.get().command()).last().isEqualTo("mirror.internal:5000/acme-lint@" + DIGEST);
            assertThat(verified.get().image())
                    .isEqualTo("mirror.internal:5000/sigstore/cosign/cosign@" + ImageSignatureVerifier.COSIGN.split("@")[1]);
        }

        @Test
        @DisplayName("an executor that requires a signer refuses a plugin that declares none, and starts no container")
        void required() {
            plugin(0, writing(REPORT));
            PluginManifest unsigned = manifest(Set.of(Language.PYTHON));

            List<PluginStep> steps = new PluginSteps(scannerWith(new PluginScanner.Settings(null, true)), reference -> unsigned)
                    .run(List.of(ref(unsigned)), workspace, workspace.source());

            assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Refused.class, refused -> {
                assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.UNSIGNED);
                assertThat(refused.reason()).contains("VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED").contains("waived");
            });
            verify(containers, never()).run(any());
        }

        @Test
        @DisplayName("the default executor requires a signer: an unsigned plugin is refused without a word of configuration")
        void requiredByDefault() {
            plugin(0, writing(REPORT));
            PluginManifest unsigned = manifest(Set.of(Language.PYTHON));

            List<PluginStep> steps = new PluginSteps(scannerWith(PluginScanner.Settings.DEFAULT), reference -> unsigned)
                    .run(List.of(ref(unsigned)), workspace, workspace.source());

            assertThat(steps).singleElement().isInstanceOf(PluginStep.Refused.class);
            verify(containers, never()).run(any());
        }

        @Test
        @DisplayName("a plugin the governor waived runs unsigned where a signer is required, and says it was waived")
        void waived() {
            plugin(0, writing(REPORT));
            PluginManifest unsigned = manifest(Set.of(Language.PYTHON));

            List<PluginStep> steps = new PluginSteps(scannerWith(PluginScanner.Settings.DEFAULT), reference -> unsigned)
                    .run(List.of(new PluginRef(unsigned.id(), unsigned.digest(), true)), workspace, workspace.source());

            assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Produced.class, produced -> {
                assertThat(produced.signature()).isEqualTo(PluginStep.Signature.WAIVED);
                assertThat(produced.findings()).hasSize(1);
            });
            assertThat(verified.get()).as("nothing to verify: no signer was declared").isNull();
            assertThat(launched.get()).isNotNull();
        }

        @Test
        @DisplayName("an executor that requires a signer runs a plugin that declares one, once it is verified")
        void requiredAndSigned() {
            plugin(0, writing(REPORT));

            List<PluginStep> steps = new PluginSteps(scannerWith(new PluginScanner.Settings(null, true)), reference -> keyless)
                    .run(List.of(ref(keyless)), workspace, workspace.source());

            assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Produced.class, produced ->
                    assertThat(produced.signature()).isEqualTo(PluginStep.Signature.VERIFIED));
            assertThat(verified.get()).isNotNull();
        }

        @Test
        @DisplayName("without a declared signer and without the requirement, nothing is verified, and the step says so")
        void undeclared() {
            plugin(0, writing(REPORT));

            assertThat(run(manifest(Set.of(Language.PYTHON)))).singleElement()
                    .isInstanceOfSatisfying(PluginStep.Produced.class, produced ->
                            assertThat(produced.signature()).isEqualTo(PluginStep.Signature.NOT_REQUIRED));
            assertThat(verified.get()).isNull();
        }
    }

    @Nested
    @DisplayName("not applicable")
    class NotApplicable {

        @Test
        @DisplayName("a plugin none of whose languages is in the tree is not run, and not reported as a failure")
        void notApplicable() {
            plugin(0, writing(REPORT));

            List<PluginStep> steps = run(manifest(Set.of(Language.JAVA, Language.KOTLIN)));

            assertThat(steps).containsExactly(new PluginStep.NotApplicable(
                    "acme-lint", manifest(Set.of(Language.JAVA, Language.KOTLIN)).digest(), Set.of(Language.JAVA, Language.KOTLIN)));
            verify(containers, never()).run(any());
        }
    }

    @Nested
    @DisplayName("absent")
    class Absent {

        private PluginStep.Absent absentOf(List<PluginStep> steps) {
            assertThat(steps).singleElement().isInstanceOf(PluginStep.Absent.class);
            return (PluginStep.Absent) steps.getFirst();
        }

        @Test
        @DisplayName("an exit code the manifest does not declare is a failure, with the plugin's own words")
        void undeclaredExitCode() {
            plugin(2, writing(REPORT));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason())
                    .contains("exited with 2").contains("the plugin's own complaint");
        }

        @Test
        @DisplayName("a workspace owned by root is not run as its owner: that would be running the plugin as root")
        void rootOwnedWorkspace() {
            owner = "0:0";
            plugin(0, writing(REPORT));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("runs as root here");
            verify(containers, never()).run(any());
        }

        @Test
        @DisplayName("a host that reports no owner does not run the plugin as root instead")
        void noOwner() {
            owner = null;
            plugin(0, writing(REPORT));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("reports no owner");
            verify(containers, never()).run(any());
        }

        @Test
        @DisplayName("no report is a failure, not an empty one")
        void noReport() {
            plugin(0, output -> { });

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("without writing its report");
        }

        @Test
        @DisplayName("a report left as a link is not followed: the plugin cannot make this process read a host file")
        void linkedReport(@TempDir Path elsewhere) throws IOException {
            Path secret = elsewhere.resolve("secret.sarif");
            Files.writeString(secret, REPORT);
            plugin(0, output -> {
                try {
                    Files.createSymbolicLink(output.resolve("results.sarif"), secret);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("not a regular file");
        }

        @Test
        @DisplayName("a plugin that filled its output directory is absent, whatever it exited on and wrote")
        void filled() {
            full = true;
            plugin(0, writing(REPORT));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason())
                    .contains("filled its output directory").contains("not believed");
        }

        @Test
        @DisplayName("a plugin killed for a file past its size limit is told so, not left to its exit code")
        void fileTooLarge() {
            plugin(153, writing(REPORT));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason())
                    .contains("larger than").contains("SIGXFSZ");
        }

        @Test
        @DisplayName("a report larger than the scanner output ceiling is a failure")
        void oversized() {
            when(containers.outputBytes()).thenReturn(64L);
            plugin(0, writing(REPORT));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("larger than");
        }

        @Test
        @DisplayName("a run that computed no results is absent — SARIF's own absent, not an empty list")
        void noResults() {
            plugin(0, writing("{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"acme-lint\"}}}]}"));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("computed no results");
        }

        @Test
        @DisplayName("a report with no run analysed nothing, and is absent")
        void noRun() {
            plugin(0, writing("{\"version\":\"2.1.0\",\"runs\":[]}"));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("carries no run");
        }

        @Test
        @DisplayName("one run that computed no results makes the whole report absent, not the others' findings complete")
        void oneRunWithoutResults() {
            plugin(0, writing("{\"version\":\"2.1.0\",\"runs\":["
                    + "{\"tool\":{\"driver\":{\"name\":\"a\"}},\"results\":[{\"ruleId\":\"R\"}]},"
                    + "{\"tool\":{\"driver\":{\"name\":\"b\"}}}]}"));

            absentOf(run(manifest(Set.of(Language.PYTHON))));
        }

        @Test
        @DisplayName("a run that says it failed is a failure, whatever it wrote")
        void failedRun() {
            plugin(0, writing("{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"acme-lint\"}},"
                    + "\"invocations\":[{\"executionSuccessful\":false}],\"results\":[]}]}"));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("did not execute successfully");
        }

        @Test
        @DisplayName("a report pointing outside the analysed tree is refused whole")
        void link() {
            plugin(0, writing(REPORT.replace("/repo/source/app/a.py", "https://evil.example/a.py")));

            assertThat(absentOf(run(manifest(Set.of(Language.PYTHON)))).reason()).contains("refused");
        }

        @Test
        @DisplayName("a definition that does not hash to the task's digest is not run")
        void wrongDefinition() {
            plugin(0, writing(REPORT));
            PluginManifest asked = manifest(Set.of(Language.PYTHON));
            PluginManifest served = new PluginManifest("acme-lint", "ACME", asked.image(), asked.languages(),
                    List.of("--everything"), asked.output(), asked.exitCodes(), false, null, 120);

            List<PluginStep> steps = new PluginSteps(scanner(null), reference -> served)
                    .run(List.of(ref(asked)), workspace, workspace.source());

            assertThat(absentOf(steps).reason()).contains("not the one the task names");
            verify(containers, never()).run(any());
        }

        @Test
        @DisplayName("an executor that cannot fetch a definition reports the plugin absent")
        void unfetchable() {
            PluginManifest asked = manifest(Set.of(Language.PYTHON));

            List<PluginStep> steps = new PluginSteps(scanner(null), PluginProvider.NONE)
                    .run(List.of(ref(asked)), workspace, workspace.source());

            assertThat(absentOf(steps).reason()).contains("could not be obtained");
        }

        @Test
        @DisplayName("a sub-path absent from the checkout is absent, not \"no language\"")
        void noTree() {
            PluginManifest asked = manifest(Set.of(Language.PYTHON));

            List<PluginStep> steps = new PluginSteps(scanner(null), reference -> asked)
                    .run(List.of(ref(asked)), workspace, workspace.source().resolve("missing"));

            assertThat(absentOf(steps).reason()).contains("absent from the checkout");
        }

        @Test
        @DisplayName("one plugin's failure is its own: the next one still runs")
        void independent() {
            PluginManifest broken = manifest(Set.of(Language.PYTHON));
            PluginManifest other = new PluginManifest("other", "Other", broken.image(), Set.of(Language.PYTHON),
                    List.of(), "results.sarif", Set.of(0), false, null, null);
            when(containers.run(any())).thenAnswer(invocation -> {
                ContainerRun run = invocation.getArgument(0);
                Path output = Files.createTempDirectory(root, "output");
                if (run.label().equals("plugin other")) {
                    Files.writeString(output.resolve("results.sarif"), REPORT);
                }
                return new ContainerRunner.ContainerResult("", "", 0, Optional.of(readBack(run.output(), output)));
            });

            List<PluginStep> steps = new PluginSteps(scanner(null),
                            reference -> reference.id().equals("other") ? other : broken)
                    .run(List.of(ref(broken), ref(other)), workspace, workspace.source());

            assertThat(steps).extracting(step -> step.getClass().getSimpleName()).containsExactly("Absent", "Produced");
        }
    }

    @Test
    @DisplayName("the step the runner records names the plugin; a not-applicable one records no failure")
    void artifacts() {
        ScanArtifacts.Builder builder = ScanArtifacts.builder();
        builder.plugin(new PluginStep.NotApplicable("a", DIGEST, Set.of(Language.JAVA)));
        ScanArtifacts artifacts = builder.build(Duration.ZERO);

        assertThat(artifacts.failures()).isEmpty();
        assertThat(artifacts.observedNothing())
                .as("a plugin with nothing to look at looked at nothing")
                .isTrue();
        assertThat(ScanArtifacts.builder().plugin(new PluginStep.Produced("a", DIGEST, "t", null, List.of()))
                        .build(Duration.ZERO).observedNothing())
                .as("a plugin that ran and found nothing did observe the tree")
                .isFalse();
    }

    @Test
    @DisplayName("a produced step whose findings did not arrive is absent, never empty")
    void missingFindingsAreAbsent() {
        ScanArtifacts artifacts = new ScanArtifacts(null, null, null, null, null, null, null, null, null,
                List.of(new PluginStep.Produced("a", DIGEST, "t", null, null)), null, Duration.ZERO);

        assertThat(artifacts.plugins()).singleElement().isInstanceOf(PluginStep.Absent.class);
    }

    @Test
    @DisplayName("the command captured is the one the container is created with")
    void captured() {
        plugin(0, writing(REPORT));
        run(manifest(Set.of(Language.PYTHON)));
        ArgumentCaptor<ContainerRun> captor = ArgumentCaptor.forClass(ContainerRun.class);
        verify(containers).run(captor.capture());

        assertThat(captor.getValue()).isEqualTo(launched.get());
    }
}

package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import com.github.dockerjava.api.DockerClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A plugin run against a real daemon, reporting from the inside what it could reach.
 *
 * <p>The plugin under test is a pinned busybox whose script writes a SARIF log in which every
 * "finding" is an observation of its own confinement: its uid, its network interfaces, whether it
 * could write to the image, to the analysed tree, whether it saw the Docker socket or the rest of
 * the workspace. The unit suite asserts what Vectispire <em>asks</em> the daemon for; this is what
 * the container actually got.
 *
 * <p><b>No skip guard</b>, as for the rest of this suite.
 */
@DisplayName("a plugin, against a real daemon")
class PluginScannerIntegrationTest {

    /** Pinned by digest, like every image Vectispire runs, and a plugin's image must be. */
    private static final String BUSYBOX =
            "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

    private static final ContainerRunner RUNNER = new ContainerRunner();

    /** Four MiB of output: a plugin fills it in a moment, and a report of a few hundred bytes still fits. */
    static final long SMALL_OUTPUT = 4L * 1024 * 1024;

    static final ScannerLimits SMALL_LIMITS = new ScannerLimits(
            ScannerLimits.DEFAULT.memory(), ScannerLimits.DEFAULT.pids(), ScannerLimits.DEFAULT.timeout(),
            ScannerLimits.DEFAULT.nanoCpus(), SMALL_OUTPUT);

    static final ContainerRunner SMALL = new ContainerRunner(SMALL_LIMITS);

    /** The daemon itself, for what the runner deliberately cannot do: list what a run left behind. */
    private static final DockerClient DOCKER = DockerClients.local();

    static final String EMPTY_REPORT =
            "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"probe\"}},\"results\":[]}]}";

    /**
     * Each observation becomes a rule id: {@code uid-1000}, {@code net-lo,}, {@code rootfs-readonly}…
     * The last result is a real finding with a location under the mount, to check the path comes back
     * relative to the analysed tree.
     */
    private static final String PROBE = """
            uid=$(id -u)
            net=$(ls /sys/class/net | tr '\\n' ',')
            routes=$(ip route 2>/dev/null | wc -l | tr -d ' ')
            if touch /bin/implant 2>/dev/null; then rootfs=writable; else rootfs=readonly; fi
            if touch "$1/implant" 2>/dev/null; then source=writable; else source=readonly; fi
            if [ -e /var/run/docker.sock ] || [ -e /run/docker.sock ]; then socket=present; else socket=absent; fi
            repo=$(ls /repo | tr '\\n' ',')
            printf '#!/bin/sh\\necho ran\\n' > /tmp/payload; chmod +x /tmp/payload
            if /tmp/payload >/dev/null 2>&1; then scratch=executable; else scratch=noexec; fi
            cat > "$2" <<EOF
            {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"probe","version":"1.0"}},"results":[
              {"ruleId":"uid-$uid"},{"ruleId":"net-$net"},{"ruleId":"routes-$routes"},{"ruleId":"rootfs-$rootfs"},{"ruleId":"source-$source"},
              {"ruleId":"socket-$socket"},{"ruleId":"repo-$repo"},{"ruleId":"scratch-$scratch"},
              {"ruleId":"FOUND","level":"error","message":{"text":"found"},
               "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file://$1/app/a.py"},"region":{"startLine":1}}}]}
            ]}]}
            EOF
            """;

    @BeforeAll
    static void daemonIsReachable() {
        assertThat(RUNNER.isAvailable())
                .as("this suite needs a Docker daemon; it does not skip itself when there is none")
                .isTrue();
    }

    static PluginManifest probe(Set<Language> languages, Set<Integer> exitCodes, String script) {
        return new PluginManifest("probe", "Confinement probe", BUSYBOX, languages,
                List.of("sh", "-c", script, "probe", PluginManifest.SOURCE_PLACEHOLDER, PluginManifest.OUTPUT_PLACEHOLDER),
                "results.sarif", exitCodes, false, null, 120);
    }

    private static List<PluginStep> run(PluginManifest manifest) {
        return run(RUNNER, manifest);
    }

    static List<PluginStep> run(ContainerRunner runner, PluginManifest manifest) {
        return Workspace.withWorkspace(workspace -> {
            try {
                Files.createDirectories(workspace.source().resolve("app"));
                Files.writeString(workspace.source().resolve("app/a.py"), "eval(input())");
                // What a plugin must never see: the workspace root holds the secrets report in the clear.
                Files.writeString(workspace.root().resolve("secrets-report.json"), "{\"secret\":\"hunter2\"}");
                Path analysed = SourceFiles.within(workspace.source(), null);
                List<PluginStep> steps = new PluginSteps(new PluginScanner(runner, PluginScanner.Settings.DEFAULT),
                                reference -> manifest)
                        .run(List.of(new PluginRef(manifest.id(), manifest.digest())), workspace, analysed);
                assertThat(sizeOf(workspace.root()))
                        .as("what the plugin wrote never reached the host's disk: the workspace holds the clone alone")
                        .isLessThan(64 * 1024);
                return steps;
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
    }

    @Test
    @DisplayName("runs confined — not root, no network, read-only image and tree, noexec scratch, no socket, no workspace")
    void confined() {
        List<PluginStep> steps = run(probe(Set.of(Language.PYTHON), Set.of(0), PROBE));

        assertThat(steps).singleElement().isInstanceOf(PluginStep.Produced.class);
        PluginStep.Produced produced = (PluginStep.Produced) steps.getFirst();
        List<String> observed = produced.findings().stream().map(SarifFinding::ruleId).toList();

        assertThat(observed).noneMatch(rule -> rule.equals("uid-0")).anyMatch(rule -> rule.startsWith("uid-"));
        // Network `none`: loopback, the kernel's own tunnel stubs on some hosts, no ethernet and no route.
        assertThat(observed).filteredOn(rule -> rule.startsWith("net-")).singleElement()
                .satisfies(net -> assertThat(net).contains("lo,").doesNotContain("eth"));
        assertThat(observed).contains("routes-0", "rootfs-readonly", "source-readonly", "socket-absent", "scratch-noexec");
        assertThat(observed)
                .as("only the analysed tree and the output directory are mounted — never the workspace root")
                .contains("repo-output,source,");
        assertThat(produced.findings()).filteredOn(finding -> finding.ruleId().equals("FOUND")).singleElement()
                .satisfies(finding -> {
                    assertThat(finding.file()).isEqualTo("app/a.py");
                    assertThat(finding.line()).isEqualTo(1);
                });
        assertThat(produced.toolName()).isEqualTo("probe");
        assertThat(produced.toolVersion()).isEqualTo("1.0");
    }

    @Test
    @DisplayName("an exit code the manifest does not declare leaves the plugin absent, with its own words")
    void undeclaredExit() {
        List<PluginStep> steps = run(probe(Set.of(Language.PYTHON), Set.of(0), "echo 'rules failed to load' >&2; exit 3"));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                assertThat(absent.reason()).contains("exited with 3").contains("rules failed to load"));
    }

    @Test
    @DisplayName("a plugin that exits well without a report is absent, not clean")
    void noReport() {
        List<PluginStep> steps = run(probe(Set.of(Language.PYTHON), Set.of(0), "exit 0"));

        assertThat(steps).singleElement().isInstanceOf(PluginStep.Absent.class);
    }

    @Test
    @DisplayName("a plugin for a language the tree does not contain is not started at all")
    void notApplicable() {
        List<PluginStep> steps = run(probe(Set.of(Language.GO), Set.of(0), "exit 99"));

        assertThat(steps).singleElement().isInstanceOf(PluginStep.NotApplicable.class);
    }

    @Test
    @DisplayName("a plugin filling its output directory is stopped by the kernel, and absent — the host disk untouched")
    void fillsItsOutput() {
        // Writes until refused, then tries a perfectly good report and exits well: it is not believed,
        // because a write was refused and what it would have said is not in it.
        List<PluginStep> steps = run(SMALL, probe(Set.of(Language.PYTHON), Set.of(0),
                "dd if=/dev/zero of=\"$(dirname \"$2\")/fill\" bs=64k 2>/dev/null; echo '" + EMPTY_REPORT
                        + "' > \"$2\"; exit 0"));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                assertThat(absent.reason()).contains("filled its output directory").contains(String.valueOf(SMALL_OUTPUT)));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("a plugin creating files without end runs out of inodes, not of the host's memory, and is absent")
    void floodsItsOutput() {
        List<PluginStep> steps = run(SMALL, probe(Set.of(Language.PYTHON), Set.of(0),
                "cd \"$(dirname \"$2\")\" && seq 1 " + (ContainerRunner.OUTPUT_INODES + 100)
                        + " | xargs touch 2>/dev/null; exit 0"));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                assertThat(absent.reason()).contains("filled its output directory"));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("a sparse report of a terabyte is refused by the kernel, not archived and read back")
    void sparseFile() {
        // tmpfs would keep it in no page at all, and the daemon would archive its apparent size. The
        // `fsize` limit makes the truncate itself fail (EFBIG), so there is no such file to read.
        List<PluginStep> steps = run(SMALL, probe(Set.of(Language.PYTHON), Set.of(0), "exec truncate -s 1099511627776 \"$2\""));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                assertThat(absent.reason()).contains("File too large"));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("a plugin writing any file past the directory's size is killed by the kernel, and told so")
    void writesPastTheLimit() {
        // In its scratch space, which is larger than the output: the file-size limit is the process's,
        // so it is SIGXFSZ that answers and not a full directory. A child of the entrypoint, because the
        // kernel does not kill a namespace's first process on a default signal: that one gets EFBIG, and
        // its own words say "File too large", as in the case above.
        List<PluginStep> steps = run(SMALL, probe(Set.of(Language.PYTHON), Set.of(0),
                "dd if=/dev/zero of=/tmp/big bs=1M count=" + (2 * SMALL_OUTPUT / (1024 * 1024)) + "; exit $?"));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                assertThat(absent.reason()).contains("larger than " + SMALL_OUTPUT).contains("SIGXFSZ"));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("a report left as a link is not followed, even to a file inside the container")
    void linkedReport() {
        List<PluginStep> steps = run(probe(Set.of(Language.PYTHON), Set.of(0), "ln -s /etc/passwd \"$2\"; exit 0"));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                assertThat(absent.reason()).contains("not a regular file"));
        assertNothingLeftBehind();
    }

    @Test
    @DisplayName("an empty report within the bound is read back from the holder — ran, found nothing")
    void emptyReport() {
        List<PluginStep> steps = run(SMALL, probe(Set.of(Language.PYTHON), Set.of(0),
                "echo '" + EMPTY_REPORT + "' > \"$2\""));

        assertThat(steps).singleElement().isInstanceOfSatisfying(PluginStep.Produced.class, produced ->
                assertThat(produced.findings()).isEmpty());
        assertNothingLeftBehind();
    }

    /** Neither the plugin, nor its holder, nor the holder's volume survives the run. */
    static void assertNothingLeftBehind() {
        assertThat(DOCKER.listContainersCmd().withShowAll(true)
                        .withLabelFilter(java.util.Map.of(ContainerRunner.SCANNER_LABEL, "plugin probe")).exec())
                .as("the plugin's container is removed")
                .isEmpty();
        assertThat(DOCKER.listContainersCmd().withShowAll(true)
                        .withLabelFilter(java.util.Map.of(ContainerRunner.SCANNER_LABEL, "plugin probe (output)")).exec())
                .as("the holder is removed")
                .isEmpty();
        var volumes = DOCKER.listVolumesCmd()
                .withFilter("label", List.of(ContainerRunner.SCANNER_LABEL + "=plugin probe (output)"))
                .exec()
                .getVolumes();
        assertThat(volumes == null ? List.of() : volumes).as("and its volume with it").isEmpty();
    }

    private static long sizeOf(Path root) {
        try (var files = Files.walk(root)) {
            return files.filter(path -> Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS))
                    .mapToLong(path -> path.toFile().length())
                    .sum();
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}

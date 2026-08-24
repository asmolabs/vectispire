package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The container limits, checked against a real daemon.
 *
 * <p>Every assertion here exists because the corresponding unit test cannot make it. A record
 * carrying {@code network: false} proves nothing about what the daemon was told; these run a
 * container and look at what it can actually reach.
 *
 * <p><b>No skip guard.</b> Without a daemon this suite fails, which is the point — it is the
 * only executable proof that the security limits are applied rather than merely written down.
 */
@DisplayName("scanner containers, against a real daemon")
class ContainerRunnerIntegrationTest {

    /** Small, has a shell, and pinned like every other image Vectispire runs. */
    private static final String BUSYBOX = "busybox:1.37";

    private static final ContainerRunner RUNNER = new ContainerRunner();

    @BeforeAll
    static void daemonIsReachable() {
        assertThat(RUNNER.isAvailable())
                .as("this suite needs a Docker daemon; it does not skip itself when there is none")
                .isTrue();
    }

    private static ContainerResult run(ContainerRun request) {
        return RUNNER.run(request.withTimeout(Duration.ofSeconds(60)));
    }

    private static ContainerRun busybox(String script) {
        return ContainerRun.of(BUSYBOX, List.of("sh", "-c", script), List.of(), "integration");
    }

    @Test
    @DisplayName("pulls the image when the host does not have it")
    void pullsAMissingImage() {
        // The API's createContainer does not pull, unlike `docker run`. Nothing pre-pulled the
        // scanner images, so on a fresh host the first scan of each type died on a daemon error
        // naming a digest and nothing else.
        assertThat(run(busybox("echo pulled")).stdout()).contains("pulled");
    }

    @Test
    @DisplayName("keeps stdout and stderr apart")
    void streamsAreSeparate() {
        // One combined output would corrupt the JSON on stdout; silencing stderr would lose the
        // scanner's own explanation, which is what an operator reads when it fails.
        ContainerResult result = run(busybox("echo '{\"findings\":[]}'; echo 'warning: config' 1>&2"));

        assertThat(result.stdout()).contains("{\"findings\":[]}").doesNotContain("warning");
        assertThat(result.stderr()).contains("warning: config");
        assertThat(result.exitCode()).isZero();
    }

    @Test
    @DisplayName("the network is off unless the run asks for it")
    void networkIsOffByDefault() {
        // With `none` the container has loopback and nothing else. A scanner that leaks the
        // analysed source would need a route out, and this is the assertion that there is none.
        assertThat(run(busybox("ip -o addr | awk '{print $2}' | sort -u")).stdout())
                .contains("lo")
                .doesNotContain("eth0");
    }

    @Test
    @DisplayName("the network is there when the run asks for it")
    void networkCanBeOpened() {
        // The vulnerability matcher needs its database and the cataloguer needs the registry.
        // If this fails, those two scanners are silently offline.
        assertThat(run(busybox("ip -o addr | awk '{print $2}' | sort -u").withNetwork()).stdout())
                .contains("eth0");
    }

    @Test
    @DisplayName("every capability is dropped")
    void capabilitiesAreDropped() {
        // `cap_drop: ALL` on a record is a claim; the effective capability set inside the
        // container is the fact. These containers parse hostile input by definition.
        String effective = run(busybox("grep CapEff /proc/self/status")).stdout().trim();

        assertThat(effective).endsWith("0000000000000000");
    }

    @Test
    @DisplayName("no process can gain privileges")
    void noNewPrivileges() {
        assertThat(run(busybox("grep NoNewPrivs /proc/self/status")).stdout()).contains("NoNewPrivs:\t1");
    }

    @Test
    @DisplayName("a read-only mount cannot be written to")
    void readOnlyMountsAreReadOnly() throws IOException {
        // The source tree is mounted read-only so a scanner cannot alter what it is auditing —
        // nor plant something the next step would read.
        Path directory = Files.createTempDirectory("vectispire-ro-");
        Files.writeString(directory.resolve("file.txt"), "original");

        ContainerResult result = run(ContainerRun.of(
                BUSYBOX,
                List.of("sh", "-c", "echo tampered > /src/file.txt 2>&1 || echo refused"),
                List.of(ContainerRun.Mount.readOnly(directory.toString(), "/src")),
                "integration"));

        assertThat(result.stdout()).contains("refused");
        assertThat(Files.readString(directory.resolve("file.txt"))).isEqualTo("original");
    }

    @Test
    @DisplayName("a scanner that runs too long is stopped, not abandoned")
    void timeoutStopsTheContainer() {
        // Abandoning the wait would leave the container running indefinitely, holding its
        // memory and its processes, while Vectispire considers the scan finished.
        assertThatThrownBy(() -> RUNNER.run(busybox("sleep 120").withTimeout(Duration.ofSeconds(3))))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("exceeded");
    }

    @Test
    @DisplayName("a non-zero exit carries the scanner's own explanation")
    void failuresCarryTheirCause() {
        ContainerResult result = run(busybox("echo 'checkov: bad config' 1>&2; exit 2"));

        assertThatThrownBy(() -> ContainerRunner.parseJson(result, "iac", List.of(0)))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("checkov: bad config");
    }

    @Test
    @DisplayName("every container Vectispire starts is labelled")
    void containersAreLabelled() {
        // An agent runs on a shared host where other containers come and go. With no mark,
        // neither an operator nor an orphan sweep can tell what Vectispire launched from the rest.
        assertThat(ContainerRunner.SCANNER_LABEL).isEqualTo("dev.vectispire.scanner");
    }
}

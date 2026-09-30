package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Ports;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A plugin run through the socket proxy the composition ships, filtered as it is filtered there.
 *
 * <p>The bounded output is a set of calls no scanner made before: a container created with a
 * {@code Mounts} volume and one with {@code VolumesFrom}, a {@code fsize} ulimit, the archive read
 * back, a stop, a removal with {@code v=1}. Each of them passes the proxy or every plugin is absent on
 * a real installation, and the direct daemon of the other suites cannot say which. So the proxy is
 * started here with the environment {@code docker-compose.yml} gives it — {@code VOLUMES: 0}
 * included, which is the point: the volume is declared inside the create, and no {@code /volumes}
 * call is made.
 *
 * <p><b>No skip guard</b>, as for the rest of this suite.
 */
@DisplayName("a plugin, through the socket proxy")
class SocketProxyIntegrationTest {

    /**
     * These plugins declare no signer, and what they exercise is the run, not its admission: the
     * executor's default now refuses them (decision 0017 §9.1), so they run on one whose operator
     * switched the requirement off — the admission itself is {@code PluginSignatureIntegrationTest}'s.
     */
    private static final PluginScanner.Settings UNSIGNED_ALLOWED = new PluginScanner.Settings(null, false);


    /** The composition's pin, the same digest. */
    private static final String PROXY =
            "tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2";

    /** `docker-compose.yml`'s `docker-proxy` environment, line for line. */
    private static final List<String> FILTER = List.of(
            "PING=1", "VERSION=1", "INFO=1", "CONTAINERS=1", "IMAGES=1", "POST=1",
            "EXEC=0", "AUTH=0", "SECRETS=0", "CONFIGS=0", "SWARM=0", "NODES=0", "SERVICES=0", "TASKS=0",
            "VOLUMES=0", "NETWORKS=0", "PLUGINS=0", "SYSTEM=0", "DISTRIBUTION=0", "BUILD=0", "COMMIT=0", "SESSION=0");

    private static final DockerClient DOCKER = DockerClients.local();
    private static String proxy;
    private static String proxyHost;
    private static ContainerRunner throughProxy;

    @BeforeAll
    static void startProxy() throws InterruptedException {
        try {
            DOCKER.inspectImageCmd(PROXY).exec();
        } catch (NotFoundException absent) {
            DOCKER.pullImageCmd(PROXY).start().awaitCompletion();
        }
        ExposedPort api = ExposedPort.tcp(2375);
        Ports ports = new Ports();
        ports.bind(api, Ports.Binding.bindIp("127.0.0.1"));
        proxy = DOCKER.createContainerCmd(PROXY)
                .withEnv(FILTER)
                .withExposedPorts(api)
                .withHostConfig(HostConfig.newHostConfig()
                        .withBinds(Bind.parse("/var/run/docker.sock:/var/run/docker.sock:ro"))
                        .withPortBindings(ports))
                .exec()
                .getId();
        DOCKER.startContainerCmd(proxy).exec();
        String port = DOCKER.inspectContainerCmd(proxy).exec().getNetworkSettings().getPorts().getBindings()
                .get(api)[0].getHostPortSpec();
        proxyHost = "tcp://127.0.0.1:" + port;
        // The runner's own client, not the suite's: what goes through the proxy here is what the
        // composition sends through it.
        DockerClient proxied = ContainerRunner.clientAt(proxyHost);
        throughProxy = new ContainerRunner(proxied, PluginScannerIntegrationTest.SMALL_LIMITS);
        for (int attempt = 0; attempt < 50 && !throughProxy.isAvailable(); attempt++) {
            Thread.sleep(200);
        }
        assertThat(throughProxy.isAvailable()).as("the proxy answers").isTrue();
        assertThatThrownBy(() -> proxied.listVolumesCmd().exec())
                .as("and filters: the volumes API is closed, so the bound cannot be relying on it")
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("403");
    }

    @AfterAll
    static void stopProxy() {
        if (proxy != null) {
            DOCKER.removeContainerCmd(proxy).withForce(true).exec();
        }
    }

    private static PluginStep run(String script) {
        var manifest = PluginScannerIntegrationTest.probe(Set.of(Language.PYTHON), Set.of(0), script);
        return Workspace.withWorkspace(workspace -> {
            try {
                Files.createDirectories(workspace.source());
                Files.writeString(workspace.source().resolve("a.py"), "print(1)");
                List<PluginStep> steps = new PluginSteps(new PluginScanner(throughProxy, UNSIGNED_ALLOWED),
                                reference -> manifest)
                        .run(List.of(new PluginRef(manifest.id(), manifest.digest())), workspace,
                                SourceFiles.within(workspace.source(), null));
                return steps.getFirst();
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
    }

    /**
     * The proxy closes a connection ten seconds after its last response ({@code timeout
     * http-keep-alive 10s}); a pooled client that reuses it sends its next request into a closed
     * socket, and a {@code POST} is not retried. One request, a pause past the proxy's timeout, then a
     * {@code POST} as the very next call — the one order that hands it the stale connection.
     */
    @Test
    @DisplayName("a request after the proxy's idle timeout goes out on a live connection")
    void afterAPause() throws InterruptedException {
        DockerClient client = ContainerRunner.clientAt(proxyHost);
        client.pingCmd().exec();
        Thread.sleep(12_000);

        String created = client.createContainerCmd(PROXY)
                .withLabels(java.util.Map.of(ContainerRunner.SCANNER_LABEL, "idle-connection probe"))
                .exec()
                .getId();
        DOCKER.removeContainerCmd(created).withForce(true).exec();
    }

    @Test
    @DisplayName("every call of the bounded output passes the filter: the report is read back")
    void produced() {
        assertThat(run("echo '" + PluginScannerIntegrationTest.EMPTY_REPORT + "' > \"$2\""))
                .isInstanceOf(PluginStep.Produced.class);
        PluginScannerIntegrationTest.assertNothingLeftBehind();
    }

    @Test
    @DisplayName("and the bound holds there too: a plugin filling its directory is absent")
    void filled() {
        assertThat(run("dd if=/dev/zero of=\"$(dirname \"$2\")/fill\" bs=64k 2>/dev/null; echo '"
                        + PluginScannerIntegrationTest.EMPTY_REPORT + "' > \"$2\"; exit 0"))
                .isInstanceOfSatisfying(PluginStep.Absent.class, absent ->
                        assertThat(absent.reason()).contains("filled its output directory"));
        PluginScannerIntegrationTest.assertNothingLeftBehind();
    }
}

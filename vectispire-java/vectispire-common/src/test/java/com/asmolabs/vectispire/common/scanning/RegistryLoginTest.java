package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.InspectImageCmd;
import com.github.dockerjava.api.command.LogContainerCmd;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.command.PullImageCmd;
import com.github.dockerjava.api.model.AuthConfig;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.StreamType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

/**
 * The pull credentials handed to a tool for one registry — cosign, verifying a signature in a
 * registry that serves nothing anonymously.
 *
 * <p>Asserted on what the daemon is asked for, as {@link ContainerHardeningTest} does: the file is
 * read <em>while the container is being created</em>, which is the one moment it exists.
 */
@DisplayName("a registry login handed to a tool")
class RegistryLoginTest {

    private static final String IMAGE = "registry.acme.internal:5000/acme-lint@sha256:" + "d".repeat(64);
    private static final String PASSWORD = "s3cret-pull-password";

    @TempDir
    Path workspace;

    private DockerClient docker;
    private CreateContainerCmd createCommand;
    private ContainerRunner runner;
    /** The login directory as the daemon would have mounted it, and what it held at that moment. */
    private final AtomicReference<String> mounted = new AtomicReference<>();
    private final AtomicReference<String> heldFile = new AtomicReference<>();
    private final AtomicReference<String> heldMode = new AtomicReference<>();

    @BeforeEach
    void stubTheDaemon() {
        docker = mock(DockerClient.class, RETURNS_DEEP_STUBS);
        when(docker.inspectImageCmd(anyString())).thenReturn(mock(InspectImageCmd.class, RETURNS_DEEP_STUBS));
        createCommand = mock(CreateContainerCmd.class, RETURNS_SELF);
        when(createCommand.exec()).thenAnswer(invocation -> {
            ArgumentCaptor<HostConfig> config = ArgumentCaptor.forClass(HostConfig.class);
            org.mockito.Mockito.verify(createCommand).withHostConfig(config.capture());
            for (Bind bind : config.getValue().getBinds()) {
                if (bind.getVolume().getPath().equals(ContainerRunner.REGISTRY_LOGIN_MOUNT)) {
                    mounted.set(bind.getPath() + (bind.getAccessMode().toString().equals("ro") ? ":ro" : ":rw"));
                    Path file = Path.of(bind.getPath()).resolve("config.json");
                    heldFile.set(Files.readString(file));
                    heldMode.set(PosixFilePermissions.toString(Files.getPosixFilePermissions(file)) + " "
                            + PosixFilePermissions.toString(Files.getPosixFilePermissions(file.getParent())));
                }
            }
            CreateContainerResponse created = new CreateContainerResponse();
            created.setId("cosign-under-test");
            return created;
        });
        when(docker.createContainerCmd(anyString())).thenReturn(createCommand);
        runner = new ContainerRunner(docker, ScannerLimits.DEFAULT);
    }

    private void pullsSend(AuthConfig auth) {
        PullImageCmd pull = mock(PullImageCmd.class);
        when(pull.getAuthConfig()).thenReturn(auth);
        when(docker.pullImageCmd(IMAGE)).thenReturn(pull);
    }

    private void runLoggedIn() {
        try {
            runner.run(ContainerRun.of("cosign:pinned", List.of("verify", IMAGE), List.of(), "probe signature")
                    .withNetwork()
                    .runningAs("1000:1000")
                    .withRegistryLoginFor(IMAGE, workspace.resolve("signer")));
        } catch (RuntimeException expected) {
            // The stub stops short of a running container; the request is built, and the finally ran.
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> environment() {
        ArgumentCaptor<List<String>> environment = ArgumentCaptor.forClass(List.class);
        org.mockito.Mockito.verify(createCommand).withEnv(environment.capture());
        return environment.getValue();
    }

    @Test
    @DisplayName("the pull's credentials, for that registry alone, read-only, readable by their owner only")
    void handed() throws IOException {
        pullsSend(new AuthConfig().withUsername("vectispire").withPassword(PASSWORD));

        runLoggedIn();

        assertThat(mounted.get()).as("mounted, read-only").endsWith(":ro");
        JsonNode configuration = new ObjectMapper().readTree(heldFile.get());
        assertThat(configuration.path("auths").properties()).singleElement().satisfies(entry -> {
            assertThat(entry.getKey()).isEqualTo("registry.acme.internal:5000");
            assertThat(entry.getValue().path("auth").asText()).isEqualTo(Base64.getEncoder()
                    .encodeToString(("vectispire:" + PASSWORD).getBytes(StandardCharsets.UTF_8)));
        });
        assertThat(heldMode.get()).isEqualTo("rw------- rwx------");
        assertThat(environment()).contains("DOCKER_CONFIG=" + ContainerRunner.REGISTRY_LOGIN_MOUNT);
    }

    @Test
    @DisplayName("erased in the same finally that removes the container")
    void erased() throws IOException {
        pullsSend(new AuthConfig().withUsername("vectispire").withPassword(PASSWORD));

        runLoggedIn();

        assertThat(mounted.get()).isNotNull();
        try (Stream<Path> left = Files.list(workspace.resolve("signer"))) {
            assertThat(left).isEmpty();
        }
    }

    @Test
    @DisplayName("nothing held for that registry: nothing mounted, nothing named — the tool goes anonymous, as the pull would")
    void noneHeld() {
        pullsSend(null);

        runLoggedIn();

        assertThat(mounted.get()).isNull();
        assertThat(environment()).noneMatch(variable -> variable.startsWith("DOCKER_CONFIG="));
    }

    @Test
    @DisplayName("an entry left empty by a credential helper is not credentials")
    void helperEntry() {
        pullsSend(new AuthConfig().withRegistryAddress("registry.acme.internal:5000"));

        runLoggedIn();

        assertThat(mounted.get()).isNull();
    }

    @Test
    @DisplayName("a run that asks for no login gets none, whatever the configuration holds")
    void notAsked() {
        pullsSend(new AuthConfig().withUsername("vectispire").withPassword(PASSWORD));

        try {
            runner.run(ContainerRun.of("plugin:pinned", List.of(), List.of(), "probe").runningAs("1000:1000"));
        } catch (RuntimeException expected) {
            // As above.
        }

        assertThat(mounted.get()).isNull();
        assertThat(environment()).noneMatch(variable -> variable.startsWith("DOCKER_CONFIG="));
    }

    @Test
    @DisplayName("what the tool says is handed back with the credentials it quoted redacted")
    void quoted() {
        pullsSend(new AuthConfig().withUsername("vectispire").withPassword(PASSWORD));
        WaitContainerResultCallback exited = mock(WaitContainerResultCallback.class);
        when(exited.awaitStatusCode(anyLong(), any())).thenReturn(1);
        when(docker.waitContainerCmd(anyString()).start()).thenReturn(exited);
        LogContainerCmd logs = mock(LogContainerCmd.class, RETURNS_SELF);
        when(docker.logContainerCmd(anyString())).thenReturn(logs);
        when(logs.exec(any())).thenAnswer(invocation -> {
            ResultCallback<Frame> callback = invocation.getArgument(0);
            callback.onNext(new Frame(StreamType.STDERR,
                    ("Error: login with " + PASSWORD + " refused").getBytes(StandardCharsets.UTF_8)));
            callback.onComplete();
            return callback;
        });

        ContainerRunner.ContainerResult result = runner.run(
                ContainerRun.of("cosign:pinned", List.of("verify", IMAGE), List.of(), "probe signature")
                        .runningAs("1000:1000")
                        .withRegistryLoginFor(IMAGE, workspace.resolve("signer")));

        assertThat(result.stderr()).isEqualTo("Error: login with [redacted] refused");
    }

    @Test
    @DisplayName("what the runner says of a registry names it and whether credentials are held — never them")
    void access() {
        pullsSend(new AuthConfig().withUsername("vectispire").withPassword(PASSWORD));

        ContainerRunner.RegistryAccess access = runner.registryAccessFor(IMAGE);

        assertThat(access.registry()).isEqualTo("registry.acme.internal:5000");
        assertThat(access.credentialsHeld()).isTrue();
        assertThat(access.toString()).doesNotContain(PASSWORD);
    }

    @Nested
    @DisplayName("the configuration and the words")
    class Configuration {

        @Test
        @DisplayName("an identity token is handed as one, and no password is invented")
        void identityToken() throws IOException {
            JsonNode entry = new ObjectMapper().readTree(PullCredentials.configuration(
                    new AuthConfig().withIdentityToken("refresh-token"), "registry.acme.internal")).path("auths")
                    .path("registry.acme.internal");

            assertThat(entry.path("identitytoken").asText()).isEqualTo("refresh-token");
            assertThat(entry.has("auth")).isFalse();
        }

        @Test
        @DisplayName("Docker Hub is keyed as the pull keys it")
        void dockerHub() {
            assertThat(PullCredentials.registryOf("busybox@sha256:" + "b".repeat(64)))
                    .isEqualTo(AuthConfig.DEFAULT_SERVER_ADDRESS);
            assertThat(PullCredentials.registryOf("ghcr.io/acme/lint@sha256:" + "b".repeat(64))).isEqualTo("ghcr.io");
        }

        @Test
        @DisplayName("a tool that quoted the password, its base64 form or a token says [redacted] instead")
        void redacted() {
            AuthConfig auth = new AuthConfig().withUsername("vectispire").withPassword(PASSWORD)
                    .withRegistrytoken("bearer-xyz");
            String basic = Base64.getEncoder().encodeToString(("vectispire:" + PASSWORD).getBytes(StandardCharsets.UTF_8));
            List<String> said = new ArrayList<>(List.of("sent " + PASSWORD, "Authorization: Basic " + basic,
                    "token bearer-xyz"));

            assertThat(said.stream().map(text -> PullCredentials.redact(text, auth)))
                    .containsExactly("sent [redacted]", "Authorization: Basic [redacted]", "token [redacted]");
        }
    }
}

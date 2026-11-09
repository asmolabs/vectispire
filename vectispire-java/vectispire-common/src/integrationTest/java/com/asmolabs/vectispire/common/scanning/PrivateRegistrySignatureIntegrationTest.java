package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.scanning.scanners.ImageSignatureVerifier;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A plugin's signer, verified in a registry that serves nothing to an anonymous pull.
 *
 * <p>A {@code registry:2} behind htpasswd, holding a copy of distroless — its keyless signature
 * copied with it by {@code cosign copy} — and nothing else: Docker Hub's anonymous
 * rate limit is too near to copy from it in a suite. The
 * verifier is handed the pull credentials of the runner it goes through: the Docker configuration
 * its client reads, here a directory of the test's own.
 *
 * <p><b>Reached by its bridge address</b>, from the verifier's container: an RFC 1918 address is
 * one cosign speaks plain HTTP to, so no certificate has to be minted. The daemon itself would not
 * pull from it (only loopback is an insecure registry by default), which is why this suite stops at
 * the verification and does not run the plugin: what is under test is what the verifier is given and
 * what it says, and the pull's credentials are the daemon's business.
 *
 * <p>Needs the internet, like the rest of the campaign — the images copied in, and Sigstore's trust
 * root. <b>No skip guard.</b>
 */
@DisplayName("a plugin's signer, in a registry that requires authentication")
class PrivateRegistrySignatureIntegrationTest {

    private static final String REGISTRY_IMAGE =
            "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373";

    /** distroless static, by index digest: signed keyless by Google's distroless identity. */
    private static final String SIGNED_DIGEST =
            "sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee";

    private static final PluginSignature DISTROLESS = new PluginSignature(
            "keyless@distroless.iam.gserviceaccount.com", "https://accounts.google.com", null);

    private static final String USER = "vectispire";
    private static final String PASSWORD = "pull-only-" + Long.toHexString(new SecureRandom().nextLong());

    private static final DockerClient DOCKER = DockerClients.local();

    private static Path scratch;
    private static String registryId;
    private static String host;

    @BeforeAll
    static void privateRegistry() throws Exception {
        assertThat(new ContainerRunner().isAvailable())
                .as("this suite needs a Docker daemon; it does not skip itself when there is none")
                .isTrue();
        scratch = Files.createTempDirectory("vectispire-private-registry");
        Path auth = Files.createDirectories(scratch.resolve("auth"));
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        Files.writeString(auth.resolve("htpasswd"),
                USER + ":" + OpenBSDBCrypt.generate(PASSWORD.toCharArray(), salt, 6) + "\n");
        auth.resolve("htpasswd").toFile().setReadable(true, false);

        pull(REGISTRY_IMAGE);
        CreateContainerResponse created = DOCKER.createContainerCmd(REGISTRY_IMAGE)
                .withEnv("REGISTRY_AUTH=htpasswd", "REGISTRY_AUTH_HTPASSWD_REALM=vectispire",
                        "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd")
                .withHostConfig(HostConfig.newHostConfig().withBinds(Bind.parse(auth + ":/auth:ro")))
                .exec();
        registryId = created.getId();
        DOCKER.startContainerCmd(registryId).exec();
        String address = DOCKER.inspectContainerCmd(registryId).exec().getNetworkSettings().getNetworks()
                .get("bridge").getIpAddress();
        host = address + ":5000";

        // Pushed with the right credentials, by the verifier's own image: `copy` brings the signature along.
        Path pushing = credentials("pushing", PASSWORD);
        cosign(pushing, "copy", "gcr.io/distroless/static-debian12@" + SIGNED_DIGEST, host + "/probe/signed");
    }

    @AfterAll
    static void removeRegistry() {
        if (registryId != null) {
            DOCKER.removeContainerCmd(registryId).withForce(true).withRemoveVolumes(true).exec();
        }
    }

    private static String signed() {
        return host + "/probe/signed@" + SIGNED_DIGEST;
    }

    @Test
    @DisplayName("with the credentials the pulls use, the signer is verified, and they are erased after the run")
    void authenticated() throws IOException {
        ContainerRunner runner = runnerReading(credentials("right", PASSWORD));
        Path keys = Files.createTempDirectory(scratch, "keys");

        assertThatCode(() -> verify(runner, signed(), DISTROLESS, keys)).doesNotThrowAnyException();
        try (Stream<Path> left = Files.list(keys)) {
            assertThat(left).as("the credentials outlive the run by nothing").isEmpty();
        }
    }

    @Test
    @DisplayName("with no credentials held, the registry's refusal is said as such — never as a missing signature")
    void anonymous() throws IOException {
        ContainerRunner runner = runnerReading(Files.createDirectories(scratch.resolve("none")));

        assertThatThrownBy(() -> verify(runner, signed(), DISTROLESS, Files.createTempDirectory(scratch, "keys")))
                .isInstanceOfSatisfying(PluginRefusedException.class, refused -> {
                    assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.REGISTRY_AUTHENTICATION_REQUIRED);
                    assertThat(refused.getMessage()).contains(host).contains("holds no credentials").contains("UNAUTHORIZED");
                });
    }

    @Test
    @DisplayName("credentials the registry refuses: the same state, said differently, and the password nowhere")
    void refusedCredentials() throws IOException {
        String wrong = "wrong-" + Long.toHexString(new SecureRandom().nextLong());
        ContainerRunner runner = runnerReading(credentials("wrong", wrong));

        assertThatThrownBy(() -> verify(runner, signed(), DISTROLESS, Files.createTempDirectory(scratch, "keys")))
                .isInstanceOfSatisfying(PluginRefusedException.class, refused -> {
                    assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.REGISTRY_AUTHENTICATION_REQUIRED);
                    assertThat(refused.getMessage()).contains("refused the credentials").doesNotContain(wrong)
                            .doesNotContain(Base64.getEncoder().encodeToString(
                                    (USER + ":" + wrong).getBytes(StandardCharsets.UTF_8)));
                });
    }

    @Test
    @DisplayName("read with the right credentials, another signer is still not verified: the registry answered")
    void anotherSigner() throws IOException {
        ContainerRunner runner = runnerReading(credentials("right-again", PASSWORD));

        assertThatThrownBy(() -> verify(runner, signed(), new PluginSignature(null, null, UNUSED_KEY),
                        Files.createTempDirectory(scratch, "keys")))
                .isInstanceOfSatisfying(PluginRefusedException.class, refused ->
                        assertThat(refused.refusal()).isEqualTo(PluginStep.Refusal.SIGNATURE_UNVERIFIED));
    }

    /** A P-256 key nobody signed anything with — {@link PluginSignatureIntegrationTest}'s. */
    private static final String UNUSED_KEY = "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhm3H+258usrgldBUFUFN9WFtNT21\n"
            + "IV1MQgw1S41uz9HTMzDeHNZ9+PsTOW6xznu1CIrVOSLBcsTdCfoM911hVg==\n"
            + "-----END PUBLIC KEY-----\n";

    private static void verify(ContainerRunner runner, String reference, PluginSignature signer, Path keys) {
        new ImageSignatureVerifier(runner).verify(reference, signer, keys,
                ContainerRun.ownerOf(keys).orElseThrow(), "probe", ImageSignatureVerifier.COSIGN);
    }

    /** A Docker configuration directory holding {@code password} for the registry. */
    private static Path credentials(String name, String password) throws IOException {
        Path directory = Files.createDirectories(scratch.resolve(name));
        String auth = Base64.getEncoder().encodeToString((USER + ":" + password).getBytes(StandardCharsets.UTF_8));
        Files.writeString(directory.resolve("config.json"),
                "{\"auths\":{\"" + host + "\":{\"auth\":\"" + auth + "\"}}}");
        directory.resolve("config.json").toFile().setReadable(true, false);
        return directory;
    }

    /** The runner an executor whose Docker configuration is {@code dockerConfig} would build. */
    private static ContainerRunner runnerReading(Path dockerConfig) {
        DefaultDockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder()
                .withDockerHost(ContainerRunner.resolveDockerHost())
                .withDockerConfig(dockerConfig.toString())
                .build();
        DockerClient client = DockerClientImpl.getInstance(config,
                new OneRequestPerConnection(new ApacheDockerHttpClient.Builder().dockerHost(config.getDockerHost()).build()));
        return new ContainerRunner(client, ScannerLimits.DEFAULT);
    }

    private static void cosign(Path dockerConfig, String... arguments) throws InterruptedException {
        pull(ImageSignatureVerifier.COSIGN);
        String id = DOCKER.createContainerCmd(ImageSignatureVerifier.COSIGN)
                .withCmd(arguments)
                .withEnv("DOCKER_CONFIG=/docker")
                .withHostConfig(HostConfig.newHostConfig().withBinds(Bind.parse(dockerConfig + ":/docker:ro")))
                .exec().getId();
        try {
            DOCKER.startContainerCmd(id).exec();
            Integer exit = DOCKER.waitContainerCmd(id).exec(new WaitContainerResultCallback())
                    .awaitStatusCode(5, TimeUnit.MINUTES);
            if (exit == null || exit != 0) {
                StringBuilder said = new StringBuilder();
                DOCKER.logContainerCmd(id).withStdOut(true).withStdErr(true).withTailAll()
                        .exec(new com.github.dockerjava.api.async.ResultCallback.Adapter<com.github.dockerjava.api.model.Frame>() {
                            @Override
                            public void onNext(com.github.dockerjava.api.model.Frame frame) {
                                said.append(new String(frame.getPayload(), StandardCharsets.UTF_8));
                            }
                        }).awaitCompletion();
                throw new AssertionError("cosign " + List.of(arguments) + " exited " + exit + ": " + said);
            }
        } finally {
            DOCKER.removeContainerCmd(id).withForce(true).exec();
        }
    }

    private static void pull(String image) throws InterruptedException {
        DOCKER.pullImageCmd(image).start().awaitCompletion();
    }
}

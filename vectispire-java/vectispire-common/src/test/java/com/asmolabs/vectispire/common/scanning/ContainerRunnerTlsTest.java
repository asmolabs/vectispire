package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A daemon on {@code tcp://} with {@code DOCKER_TLS_VERIFY} is spoken to over TLS — decision 0038.
 *
 * <p>No daemon is needed to see it: a socket that accepts the connection and reads the first byte the
 * client sends tells a TLS handshake ({@code 0x16}) from an HTTP request ({@code G} of {@code GET}).
 * The transport was built from the host alone, and the first byte was {@code G}.
 */
@DisplayName("ContainerRunner speaks TLS to a daemon that asks for it")
class ContainerRunnerTlsTest {

    private static final int TLS_HANDSHAKE_RECORD = 0x16;

    @TempDir
    Path certificates;

    @Test
    @DisplayName("a tcp:// daemon with DOCKER_TLS_VERIFY and certificates is sent a TLS handshake")
    void tcpWithTlsVerifyOpensWithAHandshake() throws Exception {
        writeCertificates(certificates);

        int first = firstByteSentBy(port -> DefaultDockerClientConfig.createDefaultConfigBuilder()
                .withDockerHost("tcp://127.0.0.1:" + port)
                .withDockerTlsVerify(true)
                .withDockerCertPath(certificates.toString())
                .build());

        assertThat(first).as("the first byte the client sent").isEqualTo(TLS_HANDSHAKE_RECORD);
    }

    @Test
    @DisplayName("without DOCKER_TLS_VERIFY the same daemon is sent plain HTTP — what the probe reads is real")
    void tcpWithoutTlsOpensWithARequest() throws Exception {
        int first = firstByteSentBy(port -> DefaultDockerClientConfig.createDefaultConfigBuilder()
                .withDockerHost("tcp://127.0.0.1:" + port)
                .withDockerTlsVerify(false)
                .build());

        assertThat(first).isEqualTo('G');
    }

    @Test
    @DisplayName("DOCKER_TLS_VERIFY with a certificate directory missing its files is refused, never downgraded")
    void missingCertificatesAreRefused() {
        DefaultDockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder()
                .withDockerHost("tcp://127.0.0.1:2376")
                .withDockerTlsVerify(true)
                .withDockerCertPath(certificates.toString())
                .build();

        assertThatThrownBy(() -> ContainerRunner.clientOf(config))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ca.pem");
    }

    private interface ConfigAt {
        DefaultDockerClientConfig at(int port);
    }

    /** Pings a client built by {@link ContainerRunner#clientOf} against a socket that only listens. */
    private static int firstByteSentBy(ConfigAt configuration) throws Exception {
        // Threads of their own, never the common pool, and the executor declared first so that it is
        // closed last: the client retries a request whose connection was reset, its second connection
        // waits in the backlog nobody accepts, and only closing the socket releases the ping.
        try (ExecutorService threads = Executors.newVirtualThreadPerTaskExecutor();
                ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                DockerClient client = ContainerRunner.clientOf(configuration.at(server.getLocalPort()))) {
            Future<Integer> first = threads.submit(() -> {
                try (Socket accepted = server.accept()) {
                    accepted.setSoTimeout(10_000);
                    return accepted.getInputStream().read();
                }
            });
            threads.submit(() -> {
                try {
                    client.pingCmd().exec();
                } catch (RuntimeException expected) {
                    // Nothing answers: the probe closes after one byte.
                }
            });
            return first.get(20, TimeUnit.SECONDS);
        }
    }

    /**
     * One self-signed P-256 certificate, as the authority and as the client's own, with BouncyCastle's
     * lightweight API — generated per run, so no private key is committed.
     */
    private static void writeCertificates(Path directory) throws Exception {
        // Named, not explicit: a key encoded with the curve's parameters spelled out is one the JDK's
        // key factory, which docker-java reads it with, refuses.
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(
                new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, NISTNamedCurves.getByName("P-256")),
                new SecureRandom()));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();

        X500Name name = new X500Name("CN=vectispire-test");
        Instant now = Instant.now();
        var signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        var digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
        byte[] certificate = new X509v3CertificateBuilder(
                        name,
                        BigInteger.ONE,
                        Date.from(now.minus(Duration.ofMinutes(1))),
                        Date.from(now.plus(Duration.ofDays(1))),
                        name,
                        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pair.getPublic()))
                .build(new BcECContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(pair.getPrivate()))
                .getEncoded();

        String certificatePem = pem("CERTIFICATE", certificate);
        Files.writeString(directory.resolve("ca.pem"), certificatePem, StandardCharsets.US_ASCII);
        Files.writeString(directory.resolve("cert.pem"), certificatePem, StandardCharsets.US_ASCII);
        Files.writeString(directory.resolve("key.pem"),
                pem("PRIVATE KEY", PrivateKeyInfoFactory.createPrivateKeyInfo(pair.getPrivate()).getEncoded()),
                StandardCharsets.US_ASCII);
    }

    private static String pem(String type, byte[] content) throws IOException {
        StringWriter out = new StringWriter();
        try (PemWriter writer = new PemWriter(out)) {
            writer.writeObject(new PemObject(type, content));
        }
        return out.toString();
    }
}

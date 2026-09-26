package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.siem.SyslogMessage;
import com.asmolabs.vectispire.core.services.outbound.OutboundJson;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Real sockets on loopback: a UDP receiver, a TCP receiver and a TLS receiver.
 *
 * <p><b>How loopback is reached without weakening anything.</b> Loopback is refused under the
 * public-only policy, which is the SIEM's default. The tests use {@link OutboundPolicy#INTERNAL_ALLOWED}
 * — the policy an operator gets by allowing private URLs, a production setting and not a test
 * switch — and a resolver that answers {@code localhost} with {@code 127.0.0.1}, so no test
 * depends on the machine's DNS. The one seam is {@link SyslogSender#SyslogSender(javax.net.ssl.SSLSocketFactory)}:
 * a trust store holding the certificate generated below, which no system store would.
 */
@DisplayName("sending a syslog message over UDP, TCP and TLS, to the pinned address")
class SyslogSenderTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final String MESSAGE = "<85>1 2026-09-26T10:00:00.000Z h vectispire - ZAN-SEC-999 - CEF:0|Vectispire|é";

    private static final OutboundUrlGuard GUARD = new OutboundUrlGuard(hostname -> List.of(new byte[] {127, 0, 0, 1}));

    private static SSLContext server;
    private static SSLContext trustingClient;

    @BeforeAll
    static void certificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keys = generator.generateKeyPair();
        X509Certificate certificate = selfSigned(keys, "localhost");

        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, null);
        identity.setKeyEntry("collector", keys.getPrivate(), "x".toCharArray(), new X509Certificate[] {certificate});
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(identity, "x".toCharArray());
        server = SSLContext.getInstance("TLS");
        server.init(keyManagers.getKeyManagers(), null, null);

        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("collector", certificate);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(anchors);
        trustingClient = SSLContext.getInstance("TLS");
        trustingClient.init(null, trustManagers.getTrustManagers(), null);
    }

    @Test
    @DisplayName("UDP: one datagram, the message unframed")
    void udp() throws Exception {
        try (DatagramSocket receiver = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            receiver.setSoTimeout((int) TIMEOUT.toMillis());

            new SyslogSender().send(SiemProtocol.SYSLOG_UDP, destination("localhost", receiver.getLocalPort()),
                    receiver.getLocalPort(), MESSAGE, TIMEOUT, "SIEM");

            DatagramPacket packet = new DatagramPacket(new byte[70_000], 70_000);
            receiver.receive(packet);
            assertThat(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8)).isEqualTo(MESSAGE);
        }
    }

    @Test
    @DisplayName("TCP: the message octet-counted, then the stream closed")
    void tcp() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> readAll(listener));

            new SyslogSender().send(SiemProtocol.SYSLOG_TCP, destination("localhost", listener.getLocalPort()),
                    listener.getLocalPort(), MESSAGE, TIMEOUT, "SIEM");

            assertThat(received.get(10, TimeUnit.SECONDS)).isEqualTo(SyslogMessage.octetCounted(MESSAGE));
        }
    }

    @Test
    @DisplayName("TLS: octet-counted inside a verified TLS 1.2+ session")
    void tls() throws Exception {
        try (SSLServerSocket listener = tlsListener()) {
            CompletableFuture<String> protocol = new CompletableFuture<>();
            CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> readAll(listener, protocol));

            new SyslogSender(trustingClient.getSocketFactory()).send(SiemProtocol.SYSLOG_TLS,
                    destination("localhost", listener.getLocalPort()), listener.getLocalPort(), MESSAGE, TIMEOUT, "SIEM");

            assertThat(received.get(10, TimeUnit.SECONDS)).isEqualTo(SyslogMessage.octetCounted(MESSAGE));
            assertThat(protocol.get(1, TimeUnit.SECONDS)).isIn("TLSv1.3", "TLSv1.2");
        }
    }

    @Test
    @DisplayName("TLS: a certificate issued to another name is refused, even from a trusted issuer")
    void tlsVerifiesTheHostName() throws Exception {
        // The certificate is trusted and names "localhost"; the collector was configured as
        // "collector.test", which resolves to the same address. Without endpoint identification the
        // handshake succeeds: any certificate a trusted CA ever issued would do.
        try (SSLServerSocket listener = tlsListener()) {
            CompletableFuture.runAsync(() -> readAll(listener, new CompletableFuture<>()));

            assertThatThrownBy(() -> new SyslogSender(trustingClient.getSocketFactory()).send(SiemProtocol.SYSLOG_TLS,
                            destination("collector.test", listener.getLocalPort()), listener.getLocalPort(), MESSAGE,
                            TIMEOUT, "SIEM"))
                    .isInstanceOf(OutboundJson.OutboundFailureException.class);
        }
    }

    @Test
    @DisplayName("TLS: a certificate the JVM's trust store does not hold is refused")
    void tlsUsesTheSystemTrustStore() throws Exception {
        try (SSLServerSocket listener = tlsListener()) {
            CompletableFuture.runAsync(() -> readAll(listener, new CompletableFuture<>()));

            assertThatThrownBy(() -> new SyslogSender().send(SiemProtocol.SYSLOG_TLS,
                            destination("localhost", listener.getLocalPort()), listener.getLocalPort(), MESSAGE,
                            TIMEOUT, "SIEM"))
                    .isInstanceOf(OutboundJson.OutboundFailureException.class);
        }
    }

    @Test
    @DisplayName("a closed port is a failure the outbox can retry, and it says where")
    void closedPortFails() throws Exception {
        int closed;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = probe.getLocalPort();
        }
        int port = closed;
        assertThatThrownBy(() -> new SyslogSender().send(SiemProtocol.SYSLOG_TCP, destination("localhost", port), port,
                        MESSAGE, TIMEOUT, "SIEM"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("localhost:" + port)
                .hasMessageContaining("unreachable");
    }

    @Test
    @DisplayName("a destination with no checked address is refused rather than resolved again")
    void noAddressIsRefused() {
        OutboundUrlGuard.Destination unresolved = new OutboundUrlGuard.Destination("nowhere:514", "nowhere", List.of());

        for (SiemProtocol protocol : List.of(SiemProtocol.SYSLOG_UDP, SiemProtocol.SYSLOG_TCP, SiemProtocol.SYSLOG_TLS)) {
            assertThatThrownBy(() -> new SyslogSender().send(protocol, unresolved, 514, MESSAGE, TIMEOUT, "SIEM"))
                    .isInstanceOf(OutboundJson.OutboundFailureException.class)
                    .hasMessageContaining("does not resolve");
        }
    }

    @Test
    @DisplayName("an event too large for one datagram is refused, not truncated")
    void oversizedDatagram() {
        String huge = "x".repeat(SyslogSender.MAX_DATAGRAM + 1);

        assertThatThrownBy(() -> new SyslogSender().send(SiemProtocol.SYSLOG_UDP, destination("localhost", 9), 9, huge,
                        TIMEOUT, "SIEM"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("does not fit");
    }

    private static OutboundUrlGuard.Destination destination(String host, int port) {
        return GUARD.validateAndResolveEndpoint(host, port, OutboundPolicy.INTERNAL_ALLOWED, "SIEM");
    }

    private static SSLServerSocket tlsListener() throws Exception {
        return (SSLServerSocket) server.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getLoopbackAddress());
    }

    private static byte[] readAll(ServerSocket listener) {
        try (Socket accepted = listener.accept()) {
            accepted.setSoTimeout((int) TIMEOUT.toMillis());
            try (InputStream in = accepted.getInputStream()) {
                return in.readAllBytes();
            }
        } catch (Exception failed) {
            throw new IllegalStateException(failed);
        }
    }

    private static byte[] readAll(SSLServerSocket listener, CompletableFuture<String> protocol) {
        try (SSLSocket accepted = (SSLSocket) listener.accept()) {
            accepted.setSoTimeout((int) TIMEOUT.toMillis());
            accepted.startHandshake();
            protocol.complete(accepted.getSession().getProtocol());
            try (InputStream in = accepted.getInputStream()) {
                return in.readAllBytes();
            }
        } catch (Exception failed) {
            protocol.completeExceptionally(failed);
            return new byte[0];
        }
    }

    /** A certificate for one DNS name, signed with BouncyCastle's lightweight API. */
    private static X509Certificate selfSigned(KeyPair keys, String dnsName) throws Exception {
        X500Name subject = new X500Name("CN=" + dnsName);
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(Duration.ofDays(1))),
                subject,
                SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

        AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
        X509CertificateHolder holder = builder.build(new BcECContentSignerBuilder(signature, digest)
                .build(PrivateKeyFactory.createKey(keys.getPrivate().getEncoded())));

        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }
}

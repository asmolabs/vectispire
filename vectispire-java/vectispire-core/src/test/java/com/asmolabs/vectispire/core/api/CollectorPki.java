package com.asmolabs.vectispire.core.api;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;

/**
 * A private CA and a syslog-over-TLS collector whose certificate it issued, for {@code 127.0.0.1} —
 * which no system trust store holds, so only a pinned CA reaches it.
 */
final class CollectorPki {

    final KeyPair caKeys;
    final String caPem;
    private final SSLContext server;

    private CollectorPki(KeyPair caKeys, String caPem, SSLContext server) {
        this.caKeys = caKeys;
        this.caPem = caPem;
        this.server = server;
    }

    /** A CA valid from yesterday for a year, and a collector certificate it signed. */
    static CollectorPki create(String caName) throws Exception {
        return create(caName, Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(365)));
    }

    static CollectorPki create(String caName, Instant notBefore, Instant notAfter) throws Exception {
        KeyPair caKeys = keys();
        X500Name ca = new X500Name("CN=" + caName);
        X509v3CertificateBuilder root = new X509v3CertificateBuilder(ca, BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore), Date.from(notAfter), ca,
                SubjectPublicKeyInfo.getInstance(caKeys.getPublic().getEncoded()));
        root.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        root.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        byte[] caDer = sign(root, caKeys);

        KeyPair leafKeys = keys();
        X509v3CertificateBuilder leaf = new X509v3CertificateBuilder(ca, BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(Duration.ofDays(1))), Date.from(Instant.now().plus(Duration.ofDays(30))),
                new X500Name("CN=collector"), SubjectPublicKeyInfo.getInstance(leafKeys.getPublic().getEncoded()));
        leaf.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.iPAddress, "127.0.0.1")));
        byte[] leafDer = sign(leaf, caKeys);

        CertificateFactory x509 = CertificateFactory.getInstance("X.509");
        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, null);
        identity.setKeyEntry("collector", leafKeys.getPrivate(), "x".toCharArray(), new X509Certificate[] {
            (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(leafDer)),
            (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(caDer))
        });
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(identity, "x".toCharArray());
        SSLContext server = SSLContext.getInstance("TLS");
        server.init(keyManagers.getKeyManagers(), null, null);

        return new CollectorPki(caKeys, pem(caDer), server);
    }

    /** A listener on loopback; {@link #received} reads one connection's bytes. */
    SSLServerSocket listen() throws Exception {
        return (SSLServerSocket) server.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getLoopbackAddress());
    }

    static CompletableFuture<byte[]> received(SSLServerSocket listener) {
        return CompletableFuture.supplyAsync(() -> {
            try (Socket accepted = listener.accept()) {
                accepted.setSoTimeout(5_000);
                try (InputStream in = accepted.getInputStream()) {
                    return in.readAllBytes();
                }
            } catch (Exception refused) {
                return new byte[0];
            }
        });
    }

    private static byte[] sign(X509v3CertificateBuilder builder, KeyPair signer) throws Exception {
        AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
        return builder.build(new BcECContentSignerBuilder(signature, digest)
                        .build(PrivateKeyFactory.createKey(signer.getPrivate().getEncoded())))
                .getEncoded();
    }

    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }
}

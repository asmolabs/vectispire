package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a collector's pinned CA is a current CA certificate, and nothing else")
class CollectorCaTest {

    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");

    @Test
    @DisplayName("a CA certificate in PEM is read: its subject, its expiry, its DER")
    void readsACa() throws Exception {
        String pem = certificate("CN=Corp Root", true, KeyUsage.keyCertSign | KeyUsage.cRLSign, NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(365)));

        CollectorCa ca = CollectorCa.parse("\n" + pem + "\n", NOW);

        assertThat(ca.subject()).isEqualTo("CN=Corp Root");
        assertThat(ca.notAfter()).isEqualTo(NOW.plus(Duration.ofDays(365)));
        assertThat(ca.anchors()).hasSize(1);
        assertThat(ca.anchors().getFirst().der()).isNotEmpty();
        assertThat(ca.pem()).isEqualTo(pem.trim());
    }

    @Test
    @DisplayName("a bundle is read whole, and its earliest expiry is the one that counts")
    void readsABundle() throws Exception {
        String root = certificate("CN=Root", true, null, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(900)));
        String issuing = certificate("CN=Issuing", true, null, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(90)));

        CollectorCa ca = CollectorCa.parse(root + issuing, NOW);

        assertThat(ca.anchors()).extracting(CollectorCa.Anchor::subject).containsExactly("CN=Root", "CN=Issuing");
        assertThat(ca.notAfter()).isEqualTo(NOW.plus(Duration.ofDays(90)));
    }

    @Test
    @DisplayName("the collector's own certificate is refused: it is not a CA")
    void refusesALeaf() throws Exception {
        String leaf = certificate("CN=collector.corp", false, null, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(30)));

        assertThatThrownBy(() -> CollectorCa.parse(leaf, NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("is not a certificate authority");
    }

    @Test
    @DisplayName("a CA whose key usage forbids signing certificates is refused")
    void refusesACaThatCannotSign() throws Exception {
        String ca = certificate("CN=Odd", true, KeyUsage.digitalSignature, NOW.minus(Duration.ofDays(1)),
                NOW.plus(Duration.ofDays(30)));

        assertThatThrownBy(() -> CollectorCa.parse(ca, NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("keyCertSign");
    }

    @Test
    @DisplayName("an expired CA is refused at the save, though the JDK would accept it as an anchor")
    void refusesAnExpiredCa() throws Exception {
        String expired = certificate("CN=Old Root", true, null, NOW.minus(Duration.ofDays(400)), NOW.minus(Duration.ofSeconds(1)));

        assertThatThrownBy(() -> CollectorCa.parse(expired, NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("expired on");
        // Still readable, so a stored one that has since expired can be shown and replaced.
        assertThat(CollectorCa.read(expired).subject()).isEqualTo("CN=Old Root");
    }

    @Test
    @DisplayName("a CA not valid yet is refused")
    void refusesAFutureCa() throws Exception {
        String future = certificate("CN=Next Root", true, null, NOW.plus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(400)));

        assertThatThrownBy(() -> CollectorCa.parse(future, NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("not valid before");
    }

    @Test
    @DisplayName("a private key is refused, and not echoed back")
    void refusesAPrivateKey() throws Exception {
        KeyPair keys = keys();
        String key = pem("PRIVATE KEY", keys.getPrivate().getEncoded());

        assertThatThrownBy(() -> CollectorCa.parse(key, NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("a private key never belongs here")
                .satisfies(refused -> assertThat(refused.getMessage()).doesNotContain(
                        Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded()).substring(0, 24)));
    }

    @Test
    @DisplayName("text with no certificate, garbage inside the armour, and an oversized bundle are refused")
    void refusesWhatIsNotABundle() throws Exception {
        assertThatThrownBy(() -> CollectorCa.parse("hello", NOW)).hasMessageContaining("holds no certificate");
        assertThatThrownBy(() -> CollectorCa.parse("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("not a readable PEM certificate");
        assertThatThrownBy(() -> CollectorCa.parse(" ", NOW)).hasMessageContaining("empty");
        assertThatThrownBy(() -> CollectorCa.parse("x".repeat(CollectorCa.MAX_LENGTH + 1), NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("at most " + CollectorCa.MAX_LENGTH);
    }

    @Test
    @DisplayName("a bundle of more certificates than a chain needs is refused")
    void refusesTooManyCertificates() throws Exception {
        String one = certificate("CN=R", true, null, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(30)));

        assertThat(CollectorCa.parse(one.repeat(CollectorCa.MAX_CERTIFICATES), NOW).anchors())
                .hasSize(CollectorCa.MAX_CERTIFICATES);
        assertThatThrownBy(() -> CollectorCa.parse(one.repeat(CollectorCa.MAX_CERTIFICATES + 1), NOW))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("more than " + CollectorCa.MAX_CERTIFICATES);
    }

    /** A self-signed certificate; {@code keyUsage} null leaves the extension out. */
    static String certificate(String subject, boolean ca, Integer keyUsage, Instant notBefore, Instant notAfter)
            throws Exception {
        KeyPair keys = keys();
        X500Name name = new X500Name(subject);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                name,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore),
                Date.from(notAfter),
                name,
                SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (keyUsage != null) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        }
        AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
        byte[] der = builder.build(new BcECContentSignerBuilder(signature, digest)
                        .build(PrivateKeyFactory.createKey(keys.getPrivate().getEncoded())))
                .getEncoded();
        return pem("CERTIFICATE", der);
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }
}

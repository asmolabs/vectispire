package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.io.IOException;
import java.io.StringReader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

/**
 * The certificate authorities a syslog-over-TLS collector is verified against, in place of the
 * Java runtime's trust store.
 *
 * <p><b>Why per collector, and why instead of the runtime's store.</b> A collector on an internal
 * network carries a certificate from the organisation's own CA, and the only way to reach it was to
 * import that CA into the JVM's {@code cacerts} — a deployment step that widened every outbound TLS
 * connection the control plane makes (trackers, models, webhooks) to trust it as well. Pinned here,
 * it is trusted for this one connection and nothing else, and the public CAs are <em>not</em>
 * trusted for it: a certificate some public CA issued for the collector's name does not pass.
 *
 * <p><b>What is refused, and why at the save.</b> A certificate that is not a CA (a leaf pasted in
 * place of its issuer would make a self-signed collector "trusted" by anyone who copied its
 * certificate, and a leaf rotates without warning), one that has expired or is not yet valid — the
 * JDK's path validation does not check a trust anchor's own dates, so an expired anchor would be
 * accepted silently — anything that is not a certificate (a private key pasted by mistake is
 * refused without being echoed), and a bundle past {@link #MAX_LENGTH} characters or {@link
 * #MAX_CERTIFICATES} certificates. Hostname verification is not this class's concern and is never
 * relaxed by it: the collector's certificate must still name the host as typed.
 *
 * <p>Read with BouncyCastle's lightweight API. A CA is public: it is stored as written, not
 * encrypted.
 *
 * @param pem the bundle as stored, trimmed
 * @param anchors each certificate of the bundle, in order
 */
public record CollectorCa(String pem, List<Anchor> anchors) {

    /** A generous bundle — a root and a few intermediates — and the bound the save applies. */
    public static final int MAX_LENGTH = 16_384;

    /** More than a chain needs; past it the field is holding something other than a CA. */
    public static final int MAX_CERTIFICATES = 8;

    /**
     * One certificate of the bundle.
     *
     * @param der its DER encoding, what the TLS stack is handed
     */
    public record Anchor(String subject, Instant notBefore, Instant notAfter, byte[] der) {}

    public CollectorCa {
        anchors = List.copyOf(anchors);
    }

    /**
     * Reads a bundle and checks it is usable now.
     *
     * @throws InvalidInputException worded for the person who pasted it
     */
    public static CollectorCa parse(String pem, Instant now) {
        return read(pem).requireCurrent(now);
    }

    /**
     * Reads a bundle, checking its shape but not its dates — for describing a stored one, which may
     * have expired since it was saved and must still be shown so that somebody replaces it.
     *
     * @throws InvalidInputException when the text is not a bundle of CA certificates
     */
    public static CollectorCa read(String pem) {
        String value = pem == null ? "" : pem.trim();
        if (value.isEmpty()) {
            throw new InvalidInputException("The collector CA is empty.");
        }
        if (value.length() > MAX_LENGTH) {
            throw new InvalidInputException("The collector CA is " + value.length() + " characters long; at most "
                    + MAX_LENGTH + " are accepted.");
        }
        List<Anchor> anchors = new ArrayList<>();
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object next;
            while ((next = parser.readObject()) != null) {
                if (!(next instanceof X509CertificateHolder certificate)) {
                    // The object is not named: if it is a private key, its type is all this says.
                    throw new InvalidInputException(
                            "The collector CA holds something other than certificates. Paste the CA's certificate "
                                    + "in PEM form (-----BEGIN CERTIFICATE-----); a private key never belongs here.");
                }
                if (anchors.size() == MAX_CERTIFICATES) {
                    throw new InvalidInputException(
                            "The collector CA holds more than " + MAX_CERTIFICATES + " certificates.");
                }
                anchors.add(anchorOf(certificate));
            }
        } catch (IOException | RuntimeException unreadable) {
            if (unreadable instanceof InvalidInputException refused) {
                throw refused;
            }
            throw new InvalidInputException("The collector CA is not a readable PEM certificate.");
        }
        if (anchors.isEmpty()) {
            throw new InvalidInputException(
                    "The collector CA holds no certificate. Paste it in PEM form, -----BEGIN CERTIFICATE----- "
                            + "included.");
        }
        return new CollectorCa(value, anchors);
    }

    /**
     * This bundle, when every certificate of it is valid at {@code now}.
     *
     * @throws InvalidInputException naming the certificate that is not
     */
    public CollectorCa requireCurrent(Instant now) {
        for (Anchor anchor : anchors) {
            if (!now.isBefore(anchor.notAfter())) {
                throw new InvalidInputException("The collector CA \"" + anchor.subject() + "\" expired on "
                        + anchor.notAfter() + ".");
            }
            if (now.isBefore(anchor.notBefore())) {
                throw new InvalidInputException("The collector CA \"" + anchor.subject() + "\" is not valid before "
                        + anchor.notBefore() + ".");
            }
        }
        return this;
    }

    /** The first certificate's subject: what the screen shows to say which CA is pinned. */
    public String subject() {
        return anchors.getFirst().subject();
    }

    /** The earliest expiry of the bundle: past it, the collector is no longer reachable. */
    public Instant notAfter() {
        return anchors.stream().map(Anchor::notAfter).min(Comparator.naturalOrder()).orElseThrow();
    }

    private static Anchor anchorOf(X509CertificateHolder certificate) throws IOException {
        String subject = certificate.getSubject().toString();
        BasicConstraints constraints = BasicConstraints.fromExtensions(certificate.getExtensions());
        if (constraints == null || !constraints.isCA()) {
            throw new InvalidInputException("\"" + subject + "\" is not a certificate authority (its basic "
                    + "constraints do not say CA): pin the CA that issued the collector's certificate, not the "
                    + "collector's own.");
        }
        KeyUsage usage = KeyUsage.fromExtensions(certificate.getExtensions());
        if (usage != null && !usage.hasUsages(KeyUsage.keyCertSign)) {
            throw new InvalidInputException("\"" + subject + "\" may not sign certificates (its key usage lacks "
                    + "keyCertSign), so it cannot have issued the collector's.");
        }
        return new Anchor(
                subject,
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant(),
                certificate.getEncoded());
    }
}

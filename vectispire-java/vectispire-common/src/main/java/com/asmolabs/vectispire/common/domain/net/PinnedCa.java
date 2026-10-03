package com.asmolabs.vectispire.common.domain.net;

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
 * The certificate authorities one outbound TLS destination is verified against, in place of the Java
 * runtime's trust store — a SIEM collector, a self-managed forge.
 *
 * <p><b>Why per destination, and why instead of the runtime's store.</b> A server on an internal network
 * carries a certificate from the organisation's own CA, and the only way to reach it was to import that
 * CA into the JVM's {@code cacerts} — a deployment step that widened every outbound TLS connection the
 * control plane makes (trackers, models, webhooks) to trust it as well. Pinned to one destination, it is
 * trusted for that destination and nothing else, and the public CAs are <em>not</em> trusted for it: a
 * certificate some public CA issued for the server's name does not pass. The alternative an
 * administrator facing a private CA reaches for — "skip verification" — exists nowhere here: it would
 * hand the token sent to that server to whoever answers first on the path.
 *
 * <p><b>What is refused, and why at the save.</b> A certificate that is not a CA (a leaf pasted in
 * place of its issuer would make a self-signed server "trusted" by anyone who copied its certificate,
 * and a leaf rotates without warning), one that has expired or is not yet valid — the JDK's path
 * validation does not check a trust anchor's own dates, so an expired anchor would be accepted
 * silently — anything that is not a certificate (a private key pasted by mistake is refused without
 * being echoed), and a bundle past {@link #MAX_LENGTH} characters or {@link #MAX_CERTIFICATES}
 * certificates. Hostname verification is not this class's concern and is never relaxed by it: the
 * server's certificate must still name the host as typed.
 *
 * <p>Read with BouncyCastle's lightweight API. A CA is public: it is stored as written, not encrypted.
 * Extracted from the SIEM's collector CA when the forge connections (decision 0037) needed the same
 * rule; the collector's keeps its wording through {@link Subject}.
 *
 * @param pem the bundle as stored, trimmed
 * @param anchors each certificate of the bundle, in order
 */
public record PinnedCa(String pem, List<Anchor> anchors) {

    /** A generous bundle — a root and a few intermediates — and the bound the save applies. */
    public static final int MAX_LENGTH = 16_384;

    /** More than a chain needs; past it the field is holding something other than a CA. */
    public static final int MAX_CERTIFICATES = 8;

    /**
     * Who the messages speak of, so that each screen's refusal names its own field.
     *
     * @param field how the field is called at the start of a sentence — "The collector CA"
     * @param server the server whose certificate the CA must have issued — "the collector"
     */
    public record Subject(String field, String server) {}

    /**
     * One certificate of the bundle.
     *
     * @param der its DER encoding, what the TLS stack is handed
     */
    public record Anchor(String subject, Instant notBefore, Instant notAfter, byte[] der) {}

    public PinnedCa {
        anchors = List.copyOf(anchors);
    }

    /**
     * Reads a bundle and checks it is usable now.
     *
     * @throws InvalidInputException worded for the person who pasted it
     */
    public static PinnedCa parse(String pem, Instant now, Subject subject) {
        return read(pem, subject).requireCurrent(now, subject);
    }

    /**
     * Reads a bundle, checking its shape but not its dates — for describing a stored one, which may
     * have expired since it was saved and must still be shown so that somebody replaces it.
     *
     * @throws InvalidInputException when the text is not a bundle of CA certificates
     */
    public static PinnedCa read(String pem, Subject subject) {
        String value = pem == null ? "" : pem.trim();
        if (value.isEmpty()) {
            throw new InvalidInputException(subject.field() + " is empty.");
        }
        if (value.length() > MAX_LENGTH) {
            throw new InvalidInputException(subject.field() + " is " + value.length() + " characters long; at most "
                    + MAX_LENGTH + " are accepted.");
        }
        List<Anchor> anchors = new ArrayList<>();
        try (PEMParser parser = new PEMParser(new StringReader(value))) {
            Object next;
            while ((next = parser.readObject()) != null) {
                if (!(next instanceof X509CertificateHolder certificate)) {
                    // The object is not named: if it is a private key, its type is all this says.
                    throw new InvalidInputException(subject.field() + " holds something other than certificates. "
                            + "Paste the CA's certificate in PEM form (-----BEGIN CERTIFICATE-----); a private key "
                            + "never belongs here.");
                }
                if (anchors.size() == MAX_CERTIFICATES) {
                    throw new InvalidInputException(
                            subject.field() + " holds more than " + MAX_CERTIFICATES + " certificates.");
                }
                anchors.add(anchorOf(certificate, subject));
            }
        } catch (IOException | RuntimeException unreadable) {
            if (unreadable instanceof InvalidInputException refused) {
                throw refused;
            }
            throw new InvalidInputException(subject.field() + " is not a readable PEM certificate.");
        }
        if (anchors.isEmpty()) {
            throw new InvalidInputException(subject.field() + " holds no certificate. Paste it in PEM form, "
                    + "-----BEGIN CERTIFICATE----- included.");
        }
        return new PinnedCa(value, anchors);
    }

    /**
     * This bundle, when every certificate of it is valid at {@code now}.
     *
     * @throws InvalidInputException naming the certificate that is not
     */
    public PinnedCa requireCurrent(Instant now, Subject subject) {
        for (Anchor anchor : anchors) {
            if (!now.isBefore(anchor.notAfter())) {
                throw new InvalidInputException(
                        subject.field() + " \"" + anchor.subject() + "\" expired on " + anchor.notAfter() + ".");
            }
            if (now.isBefore(anchor.notBefore())) {
                throw new InvalidInputException(subject.field() + " \"" + anchor.subject() + "\" is not valid before "
                        + anchor.notBefore() + ".");
            }
        }
        return this;
    }

    /** The first certificate's subject: what a screen shows to say which CA is pinned. */
    public String subject() {
        return anchors.getFirst().subject();
    }

    /** The earliest expiry of the bundle: past it, the server is no longer reachable. */
    public Instant notAfter() {
        return anchors.stream().map(Anchor::notAfter).min(Comparator.naturalOrder()).orElseThrow();
    }

    private static Anchor anchorOf(X509CertificateHolder certificate, Subject subject) throws IOException {
        String name = certificate.getSubject().toString();
        BasicConstraints constraints = BasicConstraints.fromExtensions(certificate.getExtensions());
        if (constraints == null || !constraints.isCA()) {
            throw new InvalidInputException("\"" + name + "\" is not a certificate authority (its basic "
                    + "constraints do not say CA): pin the CA that issued " + subject.server() + "'s certificate, not "
                    + subject.server() + "'s own.");
        }
        KeyUsage usage = KeyUsage.fromExtensions(certificate.getExtensions());
        if (usage != null && !usage.hasUsages(KeyUsage.keyCertSign)) {
            throw new InvalidInputException("\"" + name + "\" may not sign certificates (its key usage lacks "
                    + "keyCertSign), so it cannot have issued " + subject.server() + "'s.");
        }
        return new Anchor(
                name,
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant(),
                certificate.getEncoded());
    }
}

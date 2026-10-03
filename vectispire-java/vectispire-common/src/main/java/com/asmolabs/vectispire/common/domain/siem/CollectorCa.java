package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;

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
 * <p><b>What is refused, and why at the save</b>, is {@link PinnedCa}'s rule, which the forge
 * connections share (decision 0037); this record keeps the SIEM's types and its wording. Hostname
 * verification is never relaxed by either: the collector's certificate must still name the host as
 * typed. A CA is public: it is stored as written, not encrypted.
 *
 * @param pem the bundle as stored, trimmed
 * @param anchors each certificate of the bundle, in order
 */
public record CollectorCa(String pem, List<Anchor> anchors) {

    /** A generous bundle — a root and a few intermediates — and the bound the save applies. */
    public static final int MAX_LENGTH = PinnedCa.MAX_LENGTH;

    /** More than a chain needs; past it the field is holding something other than a CA. */
    public static final int MAX_CERTIFICATES = PinnedCa.MAX_CERTIFICATES;

    /**
     * One certificate of the bundle.
     *
     * @param der its DER encoding, what the TLS stack is handed
     */
    public record Anchor(String subject, Instant notBefore, Instant notAfter, byte[] der) {}

    public CollectorCa {
        anchors = List.copyOf(anchors);
    }

    /** How the refusals name this field; the rule itself is {@link PinnedCa}'s, shared with the forge connections. */
    static final PinnedCa.Subject SUBJECT = new PinnedCa.Subject("The collector CA", "the collector");

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
        PinnedCa read = PinnedCa.read(pem, SUBJECT);
        return new CollectorCa(read.pem(), read.anchors().stream()
                .map(anchor -> new Anchor(anchor.subject(), anchor.notBefore(), anchor.notAfter(), anchor.der()))
                .toList());
    }

    /**
     * This bundle, when every certificate of it is valid at {@code now}.
     *
     * @throws InvalidInputException naming the certificate that is not
     */
    public CollectorCa requireCurrent(Instant now) {
        new PinnedCa(pem, anchors.stream()
                .map(anchor -> new PinnedCa.Anchor(anchor.subject(), anchor.notBefore(), anchor.notAfter(), anchor.der()))
                .toList()).requireCurrent(now, SUBJECT);
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
}

package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.checklists.DocumentZip;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;

/**
 * A produced report as it is stored and handed out (decision 0035 §3): one zip, written as the checklist's
 * package is ({@link DocumentZip}, the same bytes for the same parts), holding
 *
 * <ul>
 *   <li>{@code <output>} — the plugin's file, byte for byte;
 *   <li>{@code <output>.sig} — the platform key's detached signature over it, base64 as cosign writes one, for
 *       {@code cosign verify-blob --key};
 *   <li>{@value #PROVENANCE} — the DSSE envelope of the {@link ReportProvenance} statement, signed by the same
 *       key, for {@code cosign verify-blob-attestation --key --type} {@value ReportProvenance#PREDICATE_TYPE}.
 * </ul>
 *
 * <p>The key is the caller's — the control plane's, which never leaves it — behind {@link Signer}; the assembly is
 * here so that the container suite verifies, with cosign, exactly what the control plane stores.
 */
public final class ReportPackage {

    public static final String PROVENANCE = "provenance.json";
    public static final String SIGNATURE_SUFFIX = ".sig";

    private ReportPackage() {}

    /** The platform's key, as the package needs it: a detached signature, and a DSSE envelope. */
    public interface Signer {

        /** The base64 signature over {@code payload}, as cosign writes one. */
        String sign(byte[] payload);

        /** {@code payload} wrapped and signed over DSSE's pre-authentication encoding. */
        DsseEnvelope dsse(String payloadType, byte[] payload);
    }

    /** The package and its SHA-256 — the digest the run records and the download's audit entry names. */
    public record Packed(byte[] content, String sha256) {}

    /**
     * Signs {@code output} and its provenance, and packages the three.
     *
     * @param outputName the manifest's {@code output}, a bare file name ending with its type's extension
     * @param provenance the statement; its subject must be {@code output}'s digest
     * @throws IllegalStateException for a statement about another file — a package whose provenance names
     *     something else would be a signed false claim
     */
    public static Packed sign(String outputName, byte[] output, ReportProvenance provenance, Signer signer,
            ObjectMapper json) {
        if (!Digests.sha256Hex(output).equals(provenance.subject().getFirst().digest().get("sha256"))) {
            throw new IllegalStateException("A report's provenance names another file than the one packaged.");
        }
        byte[] envelope;
        try {
            byte[] statement = json.writeValueAsBytes(provenance);
            envelope = json.writerWithDefaultPrettyPrinter()
                    .writeValueAsBytes(signer.dsse(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, statement));
        } catch (JsonProcessingException unwritable) {
            throw new IllegalStateException("A report's provenance could not be written.", unwritable);
        }
        LinkedHashMap<String, DocumentZip.Entry> parts = new LinkedHashMap<>();
        parts.put(outputName, DocumentZip.Entry.of(output));
        parts.put(outputName + SIGNATURE_SUFFIX,
                DocumentZip.Entry.of(signer.sign(output).getBytes(StandardCharsets.US_ASCII)));
        parts.put(PROVENANCE, DocumentZip.Entry.of(envelope));
        byte[] content = DocumentZip.of(parts);
        return new Packed(content, Digests.sha256Hex(content));
    }
}

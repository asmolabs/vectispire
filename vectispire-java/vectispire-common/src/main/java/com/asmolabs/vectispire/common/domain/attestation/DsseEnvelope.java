package com.asmolabs.vectispire.common.domain.attestation;

import java.util.List;

/**
 * Dead Simple Signing Envelope (DSSE, the Secure Systems Lab specification used by in-toto).
 * Used for wrapping in-toto provenance statements and supply chain attestations with non-repudiable signatures.
 */
public record DsseEnvelope(
        String payloadType,
        String payload,
        List<SignatureEntry> signatures) {

    public static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
    public static final String CYCLONEDX_PAYLOAD_TYPE = "application/vnd.cyclonedx+json";

    public record SignatureEntry(
            String keyid,
            String sig) {}
}

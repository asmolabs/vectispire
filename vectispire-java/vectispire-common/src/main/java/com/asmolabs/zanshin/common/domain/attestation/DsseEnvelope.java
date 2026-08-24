package com.asmolabs.zanshin.common.domain.attestation;

import java.util.List;

/**
 * Standard Dead Simple Signing Envelope (DSSE - RFC 9615 / CNCF in-toto specification).
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

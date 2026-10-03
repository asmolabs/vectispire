package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPackage;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportProvenance;
import com.asmolabs.vectispire.core.crypto.SigningKeyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

/**
 * A checked output signed and packaged (decision 0035 §3) by the platform's key — the one every Vectispire document
 * is signed with, so a recipient verifies a report with the commands and the public key they verify every other
 * export with.
 *
 * <p>The DSSE envelope is {@link SigningKeyService#wrapAndSignDsse}, as the evidence bundle's attestations: the
 * pre-authentication encoding the specification defines, which {@code cosign verify-blob-attestation} checks. The
 * assembly is {@link ReportPackage#sign}, which the container suite verifies with cosign. Called outside any
 * transaction: signing takes no lock, and a package nobody stores costs nothing.
 */
@Component
public class ReportPackager {

    private final SigningKeyService signing;
    private final ObjectMapper json;

    public ReportPackager(SigningKeyService signing, ObjectMapper json) {
        this.signing = signing;
        this.json = json;
    }

    /** The id of the key a package is signed with: what the provenance states before it is signed. */
    public String keyId() {
        return signing.getKeyId();
    }

    /**
     * @param outputName the manifest's {@code output}
     * @param provenance the statement, its subject {@code output}'s digest and its key {@link #keyId()}
     */
    public ReportPackage.Packed pack(String outputName, byte[] output, ReportProvenance provenance) {
        return ReportPackage.sign(outputName, output, provenance, new ReportPackage.Signer() {
            @Override
            public String sign(byte[] payload) {
                return signing.sign(payload);
            }

            @Override
            public DsseEnvelope dsse(String payloadType, byte[] payload) {
                return signing.wrapAndSignDsse(payloadType, payload);
            }
        }, json);
    }
}

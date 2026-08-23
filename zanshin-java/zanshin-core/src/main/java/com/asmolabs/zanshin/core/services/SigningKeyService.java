package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.attestation.DsseEnvelope;
import com.asmolabs.zanshin.common.domain.crypto.CosignSigner;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Manages the active cryptographic signing key for Cosign / Sigstore detached signatures
 * and in-toto DSSE attestation envelopes.
 */
@Service
public class SigningKeyService {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String publicKeyPem;
    private final String keyId;

    public SigningKeyService(@Value("${zanshin.signing.key:}") String configuredKey) {
        if (configuredKey != null && !configuredKey.isBlank()) {
            this.privateKey = CosignSigner.parsePrivateKey(configuredKey);
            // Derive public key or key pair
            KeyPair kp = CosignSigner.generateKeyPair();
            this.publicKey = kp.getPublic();
        } else {
            KeyPair keyPair = CosignSigner.generateKeyPair();
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();
        }
        this.publicKeyPem = CosignSigner.toPem(this.publicKey);
        this.keyId = CosignSigner.computeKeyId(this.publicKey);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPublicKeyPem() {
        return publicKeyPem;
    }

    public String getKeyId() {
        return keyId;
    }

    public String sign(byte[] payload) {
        return CosignSigner.sign(payload, privateKey);
    }

    public DsseEnvelope wrapAndSignDsse(String payloadType, byte[] payload) {
        return CosignSigner.wrapAndSignDsse(payloadType, payload, privateKey, keyId);
    }

    public boolean verify(byte[] payload, String base64Signature, String optionalPubPem) {
        PublicKey keyToUse = optionalPubPem != null && !optionalPubPem.isBlank()
                ? CosignSigner.parsePublicKey(optionalPubPem)
                : this.publicKey;
        return CosignSigner.verify(payload, base64Signature, keyToUse);
    }
}

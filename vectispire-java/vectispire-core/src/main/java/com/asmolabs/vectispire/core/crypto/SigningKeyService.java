package com.asmolabs.vectispire.core.crypto;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The key every Vectispire signature is made with — evidence bundles, VEX, CSAF, CycloneDX, DSSE.
 *
 * <p><b>What was wrong, twice over.</b> Without {@code vectispire.signing.key}, which nothing
 * documented and so every deployment ran without, a fresh pair was generated at each start and kept
 * nowhere: every signature made before a restart stopped verifying, and two instances signed with two
 * keys. With the key set, the published public half came from a <em>different</em>, random pair, so
 * no signature verified at all. A signature nobody can check against the key that is published is not
 * a signature.
 *
 * <p><b>Where the key comes from now.</b>
 * <ol>
 *   <li>{@code vectispire.signing.key} (PEM PKCS#8, P-256), with the public half derived from it.
 *       Set it in a deployment with more than one instance: each instance otherwise needs the same
 *       stored key, see below.
 *   <li>Otherwise the key generated on first use and kept in {@code t_setting}, encrypted under
 *       {@code ENCRYPTION_KEY} and bound to its row. The row is internal: no {@code Setting} names
 *       it, so the catalog never shows it and the settings routes refuse its key.
 * </ol>
 *
 * <p><b>Refused rather than improvised.</b> With no configured key and no {@code ENCRYPTION_KEY},
 * signing throws {@link MissingEncryptionKeyException} (412). With a stored key no configured key can
 * decrypt — {@code ENCRYPTION_KEY} lost, or rotated without keeping the old one — it throws too, and
 * never generates a replacement: a new key would overwrite the one every verifier has learned, and
 * make the documents already handed out unverifiable without a word.
 */
@Service
public class SigningKeyService {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyService.class);

    /** The internal row. Named with a dot so it can never collide with a catalog key. */
    static final String STORED_KEY = "internal.document_signing_key";

    private static final String CONTEXT = "internal:document_signing_key";

    private final String configuredKey;
    private final SettingsService settings;
    private final EncryptionService encryption;

    private volatile KeyMaterial material;

    private record KeyMaterial(PrivateKey privateKey, PublicKey publicKey, String publicKeyPem, String keyId) {
        static KeyMaterial of(PrivateKey privateKey) {
            PublicKey publicKey = CosignSigner.derivePublicKey(privateKey);
            return new KeyMaterial(privateKey, publicKey, CosignSigner.toPem(publicKey), CosignSigner.computeKeyId(publicKey));
        }
    }

    public SigningKeyService(
            @Value("${vectispire.signing.key:}") String configuredKey, SettingsService settings, EncryptionService encryption) {
        this.configuredKey = configuredKey == null ? "" : configuredKey.trim();
        this.settings = settings;
        this.encryption = encryption;
        // A configured key is checked at start: a malformed or non-P-256 key is a deployment error,
        // and discovering it on the first evidence export is discovering it too late.
        if (!this.configuredKey.isEmpty()) {
            this.material = KeyMaterial.of(CosignSigner.parsePrivateKey(this.configuredKey));
        }
    }

    public PublicKey getPublicKey() {
        return material().publicKey();
    }

    public String getPublicKeyPem() {
        return material().publicKeyPem();
    }

    public String getKeyId() {
        return material().keyId();
    }

    public String sign(byte[] payload) {
        return CosignSigner.sign(payload, material().privateKey());
    }

    public DsseEnvelope wrapAndSignDsse(String payloadType, byte[] payload) {
        KeyMaterial key = material();
        return CosignSigner.wrapAndSignDsse(payloadType, payload, key.privateKey(), key.keyId());
    }

    /** Whether {@code base64Signature} is Vectispire's signature over {@code payload}. */
    public boolean verify(byte[] payload, String base64Signature) {
        return CosignSigner.verify(payload, base64Signature, material().publicKey());
    }

    /**
     * @param keyId the key the signature was checked against — the caller's, when one was supplied
     * @param vectispireKey whether that key is Vectispire's signing key
     */
    public record Verification(boolean valid, String keyId, boolean vectispireKey, String message) {}

    /**
     * Checks a signature, against Vectispire's key or against one the caller supplies.
     *
     * <p><b>The answer names the key it was checked against.</b> It used to check against the
     * caller's key when one was given and still answer "valid and authentic" with <em>Vectispire's</em>
     * key id: anybody could sign a forged document with their own key and obtain a response — or a
     * screenshot — saying Vectispire had signed it. A supplied key is still accepted, to let a
     * reviewer check a third party's signature, but the result says whose key it is.
     */
    public Verification verify(byte[] payload, String base64Signature, String suppliedPublicKey) {
        KeyMaterial ours = material();
        if (suppliedPublicKey == null || suppliedPublicKey.isBlank()) {
            boolean valid = CosignSigner.verify(payload, base64Signature, ours.publicKey());
            return new Verification(valid, ours.keyId(), true, valid
                    ? "Signature valid: signed with Vectispire's signing key."
                    : "Signature does not match Vectispire's signing key for this payload.");
        }
        PublicKey supplied = CosignSigner.parsePublicKey(suppliedPublicKey);
        String suppliedId = CosignSigner.computeKeyId(supplied);
        boolean isOurs = suppliedId.equals(ours.keyId());
        boolean valid = CosignSigner.verify(payload, base64Signature, supplied);
        String message;
        if (!valid) {
            message = "Signature does not match the supplied key for this payload.";
        } else if (isOurs) {
            message = "Signature valid: signed with Vectispire's signing key.";
        } else {
            message = "Signature valid for the key you supplied, which is not Vectispire's signing key: this does "
                    + "not show that Vectispire signed the document.";
        }
        return new Verification(valid, suppliedId, isOurs, message);
    }

    private KeyMaterial material() {
        KeyMaterial current = material;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (material == null) {
                material = loadOrCreate();
            }
            return material;
        }
    }

    private KeyMaterial loadOrCreate() {
        String stored = settings.internalValue(STORED_KEY).orElse("").trim();
        if (!stored.isEmpty()) {
            return KeyMaterial.of(CosignSigner.parsePrivateKey(decrypt(stored)));
        }

        KeyPair generated = CosignSigner.generateKeyPair();
        // Throws MissingEncryptionKeyException without ENCRYPTION_KEY: a key that cannot be kept is
        // a key whose signatures die with this process.
        boolean inserted = settings.storeInternalIfAbsent(
                STORED_KEY, encryption.encrypt(CosignSigner.toPem(generated.getPrivate()), CONTEXT));

        // **Read back, and use what is stored.** Two instances starting together can each generate
        // a key; the first insert wins, the second is refused and never overwrites it, and both
        // sign with the row that won. A multi-instance deployment can still set
        // vectispire.signing.key and avoid the question.
        String kept = settings.internalValue(STORED_KEY).orElseThrow().trim();
        KeyMaterial key = KeyMaterial.of(CosignSigner.parsePrivateKey(decrypt(kept)));
        if (inserted) {
            log.info("Generated the document signing key {} and stored it encrypted. Keep ENCRYPTION_KEY: without it, "
                    + "this key cannot be read back and nothing can be signed.", key.keyId());
        } else {
            log.info("Another instance stored the document signing key {} first; signing with it.", key.keyId());
        }
        return key;
    }

    private String decrypt(String stored) {
        SecretCipher.Decrypted secret = encryption.inspect(stored, CONTEXT);
        if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
            throw new IllegalStateException("The stored document signing key cannot be decrypted by any configured "
                    + "ENCRYPTION_KEY. It is not replaced: a new key would make every document already signed "
                    + "unverifiable. Restore the key it was encrypted with, or set vectispire.signing.key.");
        }
        return secret.plainText();
    }
}

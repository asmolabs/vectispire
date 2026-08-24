package com.asmolabs.vectispire.common.domain.crypto;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

/**
 * Pure cryptographic utility for Cosign / Sigstore compatible digital signing,
 * verification, key management (ECDSA P-256 / SHA256withECDSA), and DSSE envelope packaging.
 */
public final class CosignSigner {

    public static final String ALGORITHM = "SHA256withECDSA";
    public static final String KEY_ALGORITHM = "EC";
    public static final String CURVE_NAME = "secp256r1";

    private CosignSigner() {}

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyGen.initialize(new ECGenParameterSpec(CURVE_NAME));
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate ECDSA P-256 key pair", e);
        }
    }

    public static String toPem(PublicKey publicKey) {
        try {
            StringWriter writer = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(publicKey);
            }
            return writer.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode public key to PEM", e);
        }
    }

    public static String toPem(PrivateKey privateKey) {
        try {
            StringWriter writer = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(privateKey, null));
            }
            return writer.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode private key to PEM", e);
        }
    }

    public static PublicKey parsePublicKey(String pemOrBase64) {
        try {
            if (pemOrBase64.contains("-----")) {
                try (PEMParser parser = new PEMParser(new StringReader(pemOrBase64))) {
                    Object parsed = parser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                    if (parsed instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo subInfo) {
                        return converter.getPublicKey(subInfo);
                    }
                }
            }
            // Strip any PEM boundary markers if raw base64 was wrapped
            String cleanBase64 = pemOrBase64.replaceAll("-----[^-]+-----", "").replaceAll("\\s+", "");
            byte[] encoded = Base64.getDecoder().decode(cleanBase64);
            KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid ECDSA public key format", e);
        }
    }

    public static PrivateKey parsePrivateKey(String pemOrBase64) {
        try {
            if (pemOrBase64.contains("-----")) {
                try (PEMParser parser = new PEMParser(new StringReader(pemOrBase64))) {
                    Object parsed = parser.readObject();
                    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                    if (parsed instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pkInfo) {
                        return converter.getPrivateKey(pkInfo);
                    }
                    if (parsed instanceof org.bouncycastle.openssl.PEMKeyPair keyPair) {
                        return converter.getKeyPair(keyPair).getPrivate();
                    }
                }
            }
            // Strip any PEM boundary markers if raw base64 was wrapped
            String cleanBase64 = pemOrBase64.replaceAll("-----[^-]+-----", "").replaceAll("\\s+", "");
            byte[] encoded = Base64.getDecoder().decode(cleanBase64);
            KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid ECDSA private key format", e);
        }
    }

    public static String computeKeyId(PublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    public static String sign(byte[] payload, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(payload);
            byte[] signatureBytes = signer.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign payload with ECDSA", e);
        }
    }

    public static boolean verify(byte[] payload, String base64Signature, PublicKey publicKey) {
        try {
            byte[] sigBytes = Base64.getDecoder().decode(base64Signature.trim());
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(payload);
            return verifier.verify(sigBytes);
        } catch (Exception e) {
            return false;
        }
    }

    public static DsseEnvelope wrapAndSignDsse(String payloadType, byte[] payloadBytes, PrivateKey privateKey, String keyId) {
        String base64Payload = Base64.getEncoder().encodeToString(payloadBytes);
        String signature = sign(payloadBytes, privateKey);
        DsseEnvelope.SignatureEntry sigEntry = new DsseEnvelope.SignatureEntry(
                keyId != null ? keyId : "vectispire-default-key",
                signature);
        return new DsseEnvelope(payloadType, base64Payload, List.of(sigEntry));
    }

    public static boolean verifyDsse(DsseEnvelope envelope, PublicKey publicKey) {
        if (envelope == null || envelope.payload() == null || envelope.signatures() == null || envelope.signatures().isEmpty()) {
            return false;
        }
        try {
            byte[] payloadBytes = Base64.getDecoder().decode(envelope.payload());
            for (DsseEnvelope.SignatureEntry sig : envelope.signatures()) {
                if (verify(payloadBytes, sig.sig(), publicKey)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}

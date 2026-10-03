package com.asmolabs.vectispire.common.domain.plugins;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Who a plugin's image must be signed by — the governor's answer to "who built this?", which the
 * digest does not give.
 *
 * <p>The image's digest says <em>what</em> runs and nothing about who made it: a governor pasting a
 * digest from a pull request vouches for bytes nobody examined. A declared signer is checked by the
 * executor, with {@code cosign verify}, before the image is pulled; an image it does not verify is
 * never run, and the plugin is refused ({@code signature_unverified}) with cosign's own words as the
 * reason.
 *
 * <h2>Two forms, exactly one of them</h2>
 *
 * <ul>
 *   <li><b>Keyless</b> — {@code identity} and {@code issuer}: the Fulcio certificate's subject (a CI
 *       workflow's URI, a service account's address) and the OIDC issuer that vouched for it, both
 *       <b>matched exactly</b>. Cosign's regular-expression forms are not offered: {@code .*acme.*}
 *       admits {@code evil-acme.example}, and an anchoring mistake is not one a review catches. Needs
 *       the registry and Sigstore's public trust root (its TUF repository) from the executor; the
 *       transparency log's inclusion is checked offline, from the signature's bundle.
 *   <li><b>Key</b> — {@code public_key}, a PEM public key (ECDSA P-256, P-384 or P-521, Ed25519, RSA
 *       of 2048 bits or more). The key is the trust root, so the transparency log is <b>not</b>
 *       consulted: an organisation signing with its own key need not publish its internal image names
 *       to a public log, and the executor needs the registry and nothing of Sigstore — the offline form.
 * </ul>
 *
 * <p><b>Part of the manifest, hence of its digest</b>: changing the signer is a new manifest, audited
 * like any other change, and an executor cannot be handed an image under a signer the governor did
 * not name.
 */
public record PluginSignature(
        String identity,
        String issuer,
        @JsonProperty("public_key") String publicKey) {

    static final int MAX_IDENTITY = 500;
    static final int MAX_KEY = 8_192;

    /** RSA below this is refused: a key the governor would be vouching for is not one anybody can factor. */
    private static final int MIN_RSA_BITS = 2048;

    private static final Set<ASN1ObjectIdentifier> CURVES =
            Set.of(SECObjectIdentifiers.secp256r1, SECObjectIdentifiers.secp384r1, SECObjectIdentifiers.secp521r1);

    /** Blank fields become absent; a key's line endings become {@code \n}, so a paste hashes as typed. */
    public PluginSignature {
        identity = blankToNull(identity);
        issuer = blankToNull(issuer);
        publicKey = publicKey == null || publicKey.isBlank()
                ? null
                : publicKey.replace("\r\n", "\n").replace('\r', '\n').strip() + "\n";
    }

    /** The form declared, which decides what {@code cosign verify} is asked. */
    public enum Form { KEYLESS, KEY }

    @JsonIgnore
    public Form form() {
        return publicKey != null ? Form.KEY : Form.KEYLESS;
    }

    /**
     * This declaration, or a refusal naming the first thing wrong with it.
     *
     * @throws InvalidPluginException meant to be shown to the governor as it is
     */
    public PluginSignature validated() {
        boolean keyless = identity != null || issuer != null;
        if (keyless == (publicKey != null)) {
            throw new InvalidPluginException("A plugin's signature is declared either keyless — an identity and its OIDC "
                    + "issuer — or by a public key, not both and not neither.");
        }
        if (keyless) {
            if (identity == null || issuer == null) {
                throw new InvalidPluginException("A keyless signature names both the certificate's identity and the OIDC "
                        + "issuer that vouched for it: either alone admits anybody the other one does.");
            }
            requireExact(identity, "The signer's identity");
            requireExact(issuer, "The signer's OIDC issuer");
            if (!issuer.startsWith("https://")) {
                throw new InvalidPluginException("The signer's OIDC issuer is an https URL, such as "
                        + "https://token.actions.githubusercontent.com.");
            }
        } else {
            requireKey(publicKey);
        }
        return this;
    }

    /** What a manifest's digest covers, in a fixed order — a scanner plugin's and a report plugin's alike. */
    public List<String> digestFields() {
        return List.of("signature/" + form().name().toLowerCase(java.util.Locale.ROOT),
                identity == null ? "" : identity,
                issuer == null ? "" : issuer,
                publicKey == null ? "" : publicKey);
    }

    /**
     * No whitespace, no control character: each value is handed to cosign as one {@code --flag=value}
     * argument, and an exact match is only exact if what is compared is what was shown.
     */
    private static void requireExact(String value, String what) {
        if (value.length() > MAX_IDENTITY) {
            throw new InvalidPluginException(what + " is at most " + MAX_IDENTITY + " characters.");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                throw new InvalidPluginException(what + " is matched exactly, and carries no space or control character.");
            }
        }
    }

    private static void requireKey(String pem) {
        if (pem.length() > MAX_KEY) {
            throw new InvalidPluginException("The signer's public key is at most " + MAX_KEY + " characters of PEM.");
        }
        for (int i = 0; i < pem.length(); i++) {
            char c = pem.charAt(i);
            if (c != '\n' && Character.isISOControl(c)) {
                throw new InvalidPluginException("The signer's public key is PEM text, with no control character but newlines.");
            }
        }
        PemObject object;
        boolean more;
        try (PemReader reader = new PemReader(new StringReader(pem))) {
            object = reader.readPemObject();
            more = object != null && reader.readPemObject() != null;
        } catch (IOException | RuntimeException malformed) {
            throw new InvalidPluginException("The signer's public key is not a readable PEM public key.");
        }
        if (object == null || !"PUBLIC KEY".equals(object.getType()) || more) {
            throw new InvalidPluginException("The signer's public key is one PEM block, BEGIN PUBLIC KEY — as "
                    + "`cosign generate-key-pair` writes cosign.pub.");
        }
        SubjectPublicKeyInfo key;
        try {
            key = SubjectPublicKeyInfo.getInstance(object.getContent());
        } catch (RuntimeException malformed) {
            throw new InvalidPluginException("The signer's public key is not a readable PEM public key.");
        }
        ASN1ObjectIdentifier algorithm = key.getAlgorithm().getAlgorithm();
        if (algorithm.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            if (!(key.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier curve) || !CURVES.contains(curve)) {
                throw new InvalidPluginException("An ECDSA signer's key is on P-256, P-384 or P-521.");
            }
        } else if (algorithm.equals(PKCSObjectIdentifiers.rsaEncryption)) {
            BigInteger modulus;
            try {
                modulus = RSAPublicKey.getInstance(key.parsePublicKey()).getModulus();
            } catch (IOException | IllegalArgumentException malformed) {
                throw new InvalidPluginException("The signer's RSA key is not readable.");
            }
            if (modulus.bitLength() < MIN_RSA_BITS) {
                throw new InvalidPluginException("An RSA signer's key has at least " + MIN_RSA_BITS + " bits.");
            }
        } else if (!algorithm.equals(EdECObjectIdentifiers.id_Ed25519)) {
            throw new InvalidPluginException("The signer's key is ECDSA, Ed25519 or RSA — the kinds cosign verifies.");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }
}

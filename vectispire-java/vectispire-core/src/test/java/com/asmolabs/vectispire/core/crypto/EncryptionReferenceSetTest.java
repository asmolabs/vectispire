package com.asmolabs.vectispire.core.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.LocalKmsProvider;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.crypto.internal.VaultKmsProvider;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.Test;

/**
 * Encryption at rest, the Vault door and the document signing key, both ways across the two implementations —
 * the reference set {@code vectispire-rust/crates/cp-crypto} is held to ({@code encryption/}).
 *
 * <p><b>Why both ways.</b> Everything this module writes is stored: an SSH key, a clone token, a TOTP seed,
 * the signing key itself. An installation that moves from Java to Rust reads every one of them with the other
 * implementation, and one that moves back reads what Rust wrote. So this side writes ciphertexts for Rust to
 * reproduce and read ({@code java-vectors.json}), and reads what Rust wrote ({@code rust-vectors.json}).
 *
 * <p><b>Reproduce, not merely read.</b> The nonce comes from a {@code SecureRandom}; here it is a stream derived
 * from a label, so the Rust side, given the same stream, must write the same bytes — the format's every detail
 * (prefix, nonce first, tag last, padding) is then pinned, not just its readability.
 *
 * <p><b>Nothing here is a key anybody uses.</b> Every key is the SHA-256 of a label both sides spell the same;
 * the passphrases say what they are. No private key is written in the clear: the signing keys appear only
 * encrypted, as {@code t_setting} holds them.
 */
class EncryptionReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    static final String KEY_LABEL = "vectispire-rust-reference:encryption-key";
    static final String CONTEXT = "ssh_key:7:private_key";
    static final String SIGNING_CONTEXT = "internal:document_signing_key";
    static final String JAVA_SIGNING_LABEL = "vectispire-rust-reference:java-signing-key";
    static final String JAVA_SEALING_LABEL = "vectispire-rust-reference:java-sealing-key";
    static final byte[] PAYLOAD = "{\"status\":\"passed\"}".getBytes(StandardCharsets.UTF_8);

    static byte[] labelled(String label) {
        return Digests.sha256(label.getBytes(StandardCharsets.UTF_8));
    }

    static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** SHA-256(label ‖ ":" ‖ counter) per call to {@code nextBytes}: {@code CryptoReferenceSetTest}'s stream. */
    static final class LabelledRandom extends SecureRandom {
        private final String label;
        private long counter;

        LabelledRandom(String label) {
            this.label = label;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            int filled = 0;
            while (filled < bytes.length) {
                byte[] block = Digests.sha256((label + ":" + counter++).getBytes(StandardCharsets.UTF_8));
                int count = Math.min(block.length, bytes.length - filled);
                System.arraycopy(block, 0, bytes, filled, count);
                filled += count;
            }
        }
    }

    static String standardKey(String label) {
        return base64(labelled(label));
    }

    static EncryptionService service(String current, List<String> previous) {
        return new EncryptionService(new EncryptionProperties(Optional.ofNullable(current), previous));
    }

    /** The service's own cipher, with the nonce stream named by {@code stream}. */
    static LocalKmsProvider writer(String configured, String stream) {
        EncryptionKey key = EncryptionKey.derive(configured);
        return new LocalKmsProvider(Optional.of(key), List.of(key), new SecretCipher(new LabelledRandom(stream)));
    }

    static void putDecrypted(ObjectNode node, Decrypted decrypted) {
        node.put("state", decrypted.state().name());
        node.put("plain", decrypted.plainText());
    }

    // ------------------------------------------------------------------------------------------ java → rust

    @Test
    void theVectorsTheRustPortReproducesAndReads() throws Exception {
        ObjectNode vectors = RustReference.object();
        vectors.put("key_label", KEY_LABEL);
        String standard = standardKey(KEY_LABEL);

        derivations(vectors.putArray("derivations"));
        contexts(vectors.putArray("contexts"), standard);
        rotations(vectors.putArray("rotations"));
        readings(vectors.putArray("readings"), standard);
        storedSecrets(vectors.putArray("stored_secrets"), standard);
        messages(vectors.putObject("messages"));
        signing(vectors.putObject("signing"), standard);
        vault(vectors.putArray("vault"));

        RustReference.expect("encryption/java-vectors.json", vectors, EncryptionReferenceSetTest.class);
    }

    /**
     * How a configured secret becomes a key: 32 bytes of base64 used as they are, anything else stretched with
     * scrypt after NFKC. Each case is written as the cipher of a known value, so a key derived differently does
     * not read it; {@code raw} says which branch Java took, so a disagreement is named rather than inferred.
     */
    private void derivations(ArrayNode out) {
        byte[] material = labelled(KEY_LABEL);
        String standard = base64(material);
        // A label whose key's base64 holds both `+` and `/`: its URL-safe spelling then differs from the standard
        // one, and a spelling mixing both alphabets can be built from it.
        String urlLabel = null;
        for (int i = 0; urlLabel == null; i++) {
            String candidate = KEY_LABEL + ":url:" + i;
            String encoded = standardKey(candidate);
            if (encoded.indexOf('+') >= 0 && encoded.indexOf('/') >= 0) {
                urlLabel = candidate;
            }
        }
        String urlStandard = standardKey(urlLabel);
        String urlSafe = Base64.getUrlEncoder().encodeToString(labelled(urlLabel));
        // The last character before the padding carries two unused bits; Java's decoder does not look at them.
        char last = standard.charAt(42);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        String trailingBits = standard.substring(0, 42) + alphabet.charAt(alphabet.indexOf(last) | 1) + "=";
        byte[] thirtyThree = Arrays.copyOf(material, 33);

        Object[][] cases = {
            {"standard", KEY_LABEL, standard},
            {"unpadded", KEY_LABEL, standard.substring(0, 43)},
            {"surrounded by white space", KEY_LABEL, " \t" + standard + " \n"},
            {"url-safe", urlLabel, urlSafe},
            {"url-safe unpadded", urlLabel, urlSafe.substring(0, 43)},
            {"two alphabets mixed", urlLabel, urlStandard.replaceFirst("\\+", "-")},
            {"unused bits set", KEY_LABEL, trailingBits},
            {"over-padded", KEY_LABEL, standard + "="},
            {"thirty-three bytes", KEY_LABEL, Base64.getEncoder().withoutPadding().encodeToString(thirtyThree)},
            {"a passphrase", null, "correct horse battery staple, invented for a test"},
            {"a passphrase with spaces around it", null, "  spaced passphrase, invented  "},
            {"compatibility forms", null, "ﬁ Ⅻ ＡＢＣ ﬀ invented"},
            {"their NFKC form", null, "fi XII ABC ff invented"},
            {"a composed accent", null, "café invented"},
            {"a decomposed accent", null, "café invented"},
            {"beyond the BMP", null, "🔑 clé invented"},
        };
        for (Object[] c : cases) {
            String name = (String) c[0];
            String label = (String) c[1];
            String configured = (String) c[2];
            ObjectNode node = out.addObject();
            node.put("name", name);
            node.put("configured", configured);
            if (label != null) {
                node.put("label", label);
                node.put("raw", EncryptionKey.derive(configured).equals(EncryptionKey.derive(standardKey(label))));
            }
            String plain = "a value written under " + name;
            String cipher = writer(configured, "vectispire-rust-reference:derivation:" + name).encrypt(plain, CONTEXT);
            node.put("plain", plain);
            node.put("context", CONTEXT);
            node.put("cipher", cipher);
            assertThat(service(configured, List.of()).inspect(cipher, CONTEXT).plainText()).isEqualTo(plain);
        }
        assertThat(urlSafe).isNotEqualTo(urlStandard);
    }

    /** One cipher per context the product writes under, from one nonce stream, in order. */
    private void contexts(ArrayNode out, String standard) {
        String[][] cases = {
            {CONTEXT, "invented deployment key material\nsecond line\n"},
            {"git_token:12:token", "invented clone token"},
            {"forge_connection:3:token", "invented forge token"},
            {"user:totp_secret:5", "INVENTEDTOTPSEEDAAAA"},
            {SIGNING_CONTEXT, "not a signing key, a stand-in"},
            {"", "no associated data at all"},
            {"é:ü:🔑", "unicode é ü 中文 🔑"},
            {CONTEXT, "x"},
        };
        LocalKmsProvider writer = writer(standard, "vectispire-rust-reference:contexts");
        EncryptionService reader = service(standard, List.of());
        for (String[] c : cases) {
            ObjectNode node = out.addObject();
            node.put("context", c[0]);
            node.put("plain", c[1]);
            String cipher = writer.encrypt(c[1], c[0]);
            node.put("cipher", cipher);
            assertThat(reader.inspect(cipher, c[0]).plainText()).isEqualTo(c[1]);
        }
        // Encrypting nothing writes nothing, with or without a key.
        assertThat(service(null, List.of()).encrypt("", CONTEXT)).isEmpty();
    }

    /**
     * Which key reads a value, as the service reports it: the current key first, a key configured twice tried
     * once, and with no current key the first previous key reported CURRENT — the list is all there is.
     */
    private void rotations(ArrayNode out) {
        String a = standardKey(KEY_LABEL + ":a");
        String b = standardKey(KEY_LABEL + ":b");
        String c = standardKey(KEY_LABEL + ":c");
        String unknown = standardKey(KEY_LABEL + ":unknown");
        Object[][] configurations = {
            {a, List.of(a, b, c)},
            {null, List.of(b, c)},
            {null, List.of()},
            {"   ", List.of(c)},
        };
        int index = 0;
        for (Object[] configuration : configurations) {
            String current = (String) configuration[0];
            @SuppressWarnings("unchecked")
            List<String> previous = (List<String>) configuration[1];
            EncryptionService service = service(current, previous);
            ObjectNode node = out.addObject();
            if (current == null) {
                node.putNull("current");
            } else {
                node.put("current", current);
            }
            ArrayNode list = node.putArray("previous");
            previous.forEach(list::add);
            node.put("configured", service.isConfigured());
            ArrayNode values = node.putArray("values");
            for (String writtenUnder : List.of(a, b, c, unknown)) {
                String plain = "written under key " + (char) ('a' + List.of(a, b, c, unknown).indexOf(writtenUnder));
                String cipher = writer(writtenUnder, "vectispire-rust-reference:rotation:" + index++).encrypt(plain, CONTEXT);
                ObjectNode value = values.addObject();
                value.put("cipher", cipher);
                value.put("context", CONTEXT);
                putDecrypted(value, service.inspect(cipher, CONTEXT));
            }
        }
    }

    /** What reads and what does not: the decoder's tolerances, the length floor, a tampered byte, the prefix. */
    private void readings(ArrayNode out, String standard) throws Exception {
        // The first stream whose cipher's base64 holds a `+` or a `/`, so that its URL-safe spelling differs.
        String written = null;
        for (int i = 0; written == null || written.chars().noneMatch(c -> c == '+' || c == '/'); i++) {
            written = writer(standard, "vectispire-rust-reference:readings:" + i).encrypt("readable!", CONTEXT);
        }
        String body = written.substring(3);
        byte[] raw = Base64.getDecoder().decode(body);
        byte[] tamperedTag = raw.clone();
        tamperedTag[tamperedTag.length - 1] ^= 1;
        byte[] tamperedNonce = raw.clone();
        tamperedNonce[0] ^= (byte) 0x80;
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        String unpadded = body.replace("=", "");
        char last = unpadded.charAt(unpadded.length() - 1);
        String unusedBits = unpadded.substring(0, unpadded.length() - 1) + alphabet.charAt(alphabet.indexOf(last) | 1)
                + body.substring(unpadded.length());

        Map<String, String> cases = new java.util.LinkedHashMap<>();
        cases.put("as written", written);
        cases.put("without its padding", "v2:" + unpadded);
        cases.put("with unused bits set", "v2:" + unusedBits);
        cases.put("with a line break", "v2:" + body.substring(0, 20) + "\n" + body.substring(20));
        cases.put("with a leading space", " " + written);
        cases.put("with a trailing space", written + " ");
        cases.put("with an upper-case prefix", "V2:" + body);
        cases.put("in the URL-safe alphabet", "v2:" + Base64.getUrlEncoder().encodeToString(raw));
        assertThat(cases.get("in the URL-safe alphabet")).isNotEqualTo(written);
        cases.put("with its tag altered", "v2:" + base64(tamperedTag));
        cases.put("with its nonce altered", "v2:" + base64(tamperedNonce));
        cases.put("cut to 27 bytes", "v2:" + base64(Arrays.copyOf(raw, 27)));
        cases.put("of nothing", "v2:" + base64(gcm(standard, new byte[0])));
        cases.put("of bytes that are not UTF-8", "v2:" + base64(gcm(standard, new byte[] {(byte) 0xff, (byte) 0xfe, (byte) 0xe2, (byte) 0x82, 0x41})));
        cases.put("under the previous format's prefix", "v1:" + body);
        cases.put("the prefix alone", "v2:");
        cases.put("in the clear", "a value stored in the clear");
        cases.put("empty", "");
        cases.put("a Vault ciphertext without Vault", "vault:v1:c3R1Yg==");

        EncryptionService service = service(standard, List.of());
        for (Map.Entry<String, String> c : cases.entrySet()) {
            ObjectNode node = out.addObject();
            node.put("name", c.getKey());
            node.put("stored", c.getValue());
            node.put("context", CONTEXT);
            node.put("is_ciphertext", EncryptionService.isCiphertext(c.getValue()));
            putDecrypted(node, service.inspect(c.getValue(), CONTEXT));
        }
    }

    /** The GCM of {@code plain} under the key and {@link #CONTEXT}, nonce zero: what SecretCipher cannot write. */
    private static byte[] gcm(String configured, byte[] plain) throws Exception {
        // The key's bytes are the configured base64's: a standard key is used as it is.
        byte[] key = Base64.getDecoder().decode(configured);
        byte[] nonce = new byte[12];
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(CONTEXT.getBytes(StandardCharsets.UTF_8));
        byte[] sealed = cipher.doFinal(plain);
        byte[] combined = new byte[nonce.length + sealed.length];
        System.arraycopy(sealed, 0, combined, nonce.length, sealed.length);
        return combined;
    }

    /** {@code readSecret}: trimmed, a legacy clear value used as it is, an unreadable one empty. */
    private void storedSecrets(ArrayNode out, String standard) {
        String written = writer(standard, "vectispire-rust-reference:stored").encrypt("kept", CONTEXT);
        EncryptionService service = service(standard, List.of());
        for (String stored : new String[] {
            written, " \t" + written + "\n", "a legacy clear value", "  a legacy clear value  ", "", "   ",
            "v2:not even base64", "vault:v1:c3R1Yg==", " " + written,
        }) {
            ObjectNode node = out.addObject();
            node.put("stored", stored);
            node.put("context", CONTEXT);
            node.put("read", service.readSecret(stored, CONTEXT, "The test credential"));
        }
    }

    /** The sentences an operator reads, word for word. */
    private void messages(ObjectNode out) throws Exception {
        out.put("missing_key", new MissingEncryptionKeyException().getMessage());
        String key = standardKey(KEY_LABEL);
        out.put("vault_without_endpoint", refusal(() -> new EncryptionService(vaultProperties(key, null, "s.stub"))));
        out.put("vault_without_token", refusal(() -> new EncryptionService(vaultProperties(key, "https://vault.invalid", null))));
        assertThatThrownBy(() -> service(null, List.of()).encrypt("x", CONTEXT))
                .isInstanceOf(MissingEncryptionKeyException.class);

        SettingsService settings = mock(SettingsService.class);
        when(settings.internalValue(SigningKeyService.STORED_KEY))
                .thenReturn(Optional.of("v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        SigningKeyService unreadable = new SigningKeyService("", settings, service(key, List.of()));
        out.put("signing_key_unreadable", refusal(() -> unreadable.sign(PAYLOAD)));
        String p384 = pem("PRIVATE KEY", p384());
        out.put("signing_key_not_p256", refusal(() -> new SigningKeyService(p384, settings, service(key, List.of()))));
        out.put("signing_key_unparsable", refusal(() -> new SigningKeyService("not a key", settings, service(key, List.of()))));
        // SEC1 (`EC PRIVATE KEY`), with and without its named curve: what is read, and what is refused.
        java.security.interfaces.ECPrivateKey p256 =
                (java.security.interfaces.ECPrivateKey) privateKey("secp256r1", JAVA_SIGNING_LABEL);
        for (Object[] c : new Object[][] {
            {"sec1_named_p256", org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1},
            {"sec1_named_p384", org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1},
            {"sec1_named_secp256k1", org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256k1},
            {"sec1_without_curve", null},
        }) {
            byte[] der = new org.bouncycastle.asn1.sec.ECPrivateKey(256, p256.getS(), (org.bouncycastle.asn1.ASN1Encodable) c[1])
                    .getEncoded();
            String sec1 = pem("EC PRIVATE KEY", der);
            try {
                out.put((String) c[0], "key id " + new SigningKeyService(sec1, settings, service(key, List.of())).getKeyId());
            } catch (RuntimeException refused) {
                out.put((String) c[0], refused.getClass().getSimpleName() + ": " + refused.getMessage());
            }
        }
    }

    /**
     * A PEM object, its markers built from the label: written out, they read as a private key to a secret scanner,
     * and these keys are a labelled scalar's.
     */
    static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n" + base64(der) + "\n-----END " + label + "-----\n";
    }

    private static EncryptionProperties vaultProperties(String key, String endpoint, String token) {
        return new EncryptionProperties(
                Optional.of(key), Optional.empty(), List.of(), Optional.empty(), Optional.of("Vault"),
                Optional.ofNullable(endpoint), Optional.ofNullable(token), Optional.empty(), Optional.empty(),
                Optional.empty());
    }

    private static String refusal(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException refused) {
            return refused.getClass().getSimpleName() + ": " + refused.getMessage();
        }
        throw new AssertionError("expected a refusal");
    }

    /** A P-384 key's PKCS#8, from a labelled scalar: what a deployment must not configure as the signing key. */
    private static byte[] p384() throws Exception {
        return privateKey("secp384r1", "vectispire-rust-reference:p384").getEncoded();
    }

    static PrivateKey privateKey(String curve, String label) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curve));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, labelled(label)), spec));
    }

    /**
     * The stored signing key as {@code SigningKeyService} writes it: the PEM, encrypted under its row's context.
     * The Rust side decrypts and parses it, derives the same public half and key id, and verifies what Java
     * signed with it. The key id is written as {@code fingerprint}: it is a digest of the public half.
     */
    private void signing(ObjectNode out, String standard) throws Exception {
        PrivateKey key = privateKey("secp256r1", JAVA_SIGNING_LABEL);
        String pem = CosignSigner.toPem(key);
        String row = writer(standard, "vectispire-rust-reference:signing").encrypt(pem, SIGNING_CONTEXT);
        SettingsService settings = mock(SettingsService.class);
        when(settings.internalValue(SigningKeyService.STORED_KEY)).thenReturn(Optional.of(row));
        SigningKeyService service = new SigningKeyService("", settings, service(standard, List.of()));

        out.put("label", JAVA_SIGNING_LABEL);
        out.put("setting", SigningKeyService.STORED_KEY);
        out.put("context", SIGNING_CONTEXT);
        out.put("row", row);
        out.put("public_pem", service.getPublicKeyPem());
        out.put("fingerprint", service.getKeyId());
        out.put("payload", new String(PAYLOAD, StandardCharsets.UTF_8));
        String signature = sign(PAYLOAD, key, "vectispire-rust-reference:signature");
        assertThat(service.verify(PAYLOAD, signature)).isTrue();
        out.put("signature", signature);
        DsseEnvelope envelope = service.wrapAndSignDsse(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, PAYLOAD);
        assertThat(envelope.signatures().getFirst().keyid()).isEqualTo(service.getKeyId());
        byte[] pae = CosignSigner.preAuthenticationEncoding(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, PAYLOAD);
        String dsseSignature = sign(pae, key, "vectispire-rust-reference:dsse");
        DsseEnvelope deterministic = new DsseEnvelope(envelope.payloadType(), envelope.payload(),
                List.of(new DsseEnvelope.SignatureEntry(service.getKeyId(), dsseSignature)));
        assertThat(CosignSigner.verifyDsse(deterministic, service.getPublicKey())).isTrue();
        out.put("dsse_payload_type", envelope.payloadType());
        out.put("dsse_payload", envelope.payload());
        out.put("dsse_signature", dsseSignature);
        out.put("pre_authentication_encoding", new String(pae, StandardCharsets.UTF_8));
        // Configured rather than stored: the same key, as `vectispire.signing.key` would carry it.
        assertThat(new SigningKeyService(pem, settings, service(standard, List.of())).getKeyId()).isEqualTo(service.getKeyId());
        // A supplied public key that is not ours verifies, and says so.
        PrivateKey other = privateKey("secp256r1", JAVA_SIGNING_LABEL + ":other");
        String otherPem = CosignSigner.toPem(CosignSigner.derivePublicKey(other));
        String otherSignature = sign(PAYLOAD, other, "vectispire-rust-reference:other-signature");
        SigningKeyService.Verification theirs = service.verify(PAYLOAD, otherSignature, otherPem);
        out.put("other_public_pem", otherPem);
        out.put("other_signature", otherSignature);
        ObjectNode verification = out.putObject("other_verification");
        verification.put("valid", theirs.valid());
        verification.put("fingerprint", theirs.keyId());
        verification.put("vectispire", theirs.vectispireKey());
        verification.put("message", theirs.message());
        ObjectNode messages = out.putObject("verification_messages");
        messages.put("ours_valid", service.verify(PAYLOAD, service.sign(PAYLOAD), null).message());
        messages.put("ours_invalid", service.verify("{}".getBytes(StandardCharsets.UTF_8), service.sign(PAYLOAD), null).message());
        messages.put("supplied_invalid", service.verify("{}".getBytes(StandardCharsets.UTF_8), CosignSigner.sign(PAYLOAD, other), otherPem).message());
        messages.put("supplied_ours_valid", service.verify(PAYLOAD, service.sign(PAYLOAD), service.getPublicKeyPem()).message());
    }

    /**
     * {@code CosignSigner.sign}'s algorithm with a labelled stream for its nonce: ECDSA draws {@code k} at random,
     * and a file that changed at every run could not be checked.
     */
    static String sign(byte[] payload, PrivateKey key, String stream) throws Exception {
        java.security.Signature signer = java.security.Signature.getInstance(CosignSigner.ALGORITHM);
        signer.initSign(key, new LabelledRandom(stream));
        signer.update(payload);
        return base64(signer.sign());
    }

    // ------------------------------------------------------------------------------------------------ vault

    /** A sender that answers by path and keeps what it was asked — the stub of {@code VaultKmsProviderTest}. */
    static final class StubSender extends PinnedHttpSender {
        final Map<String, PinnedHttpSender.Response> answers = new TreeMap<>();
        final List<ObjectNode> requests = new ArrayList<>();

        @Override
        public Response send(
                OutboundUrlGuard.Destination destination, Map<String, String> headers, String body, Duration timeout,
                String label) {
            ObjectNode request = JSON.createObjectNode();
            request.put("method", body == null ? "GET" : "POST");
            request.put("url", destination.url());
            ObjectNode sent = request.putObject("headers");
            new TreeMap<>(headers).forEach(sent::put);
            try {
                // Parsed, and its members sorted: a `Map.of` iterates in an order that changes between runs.
                request.set("body", body == null ? null : JSON.valueToTree(
                        new TreeMap<>(JSON.readValue(body, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}))));
            } catch (Exception unreadable) {
                throw new AssertionError(unreadable);
            }
            request.put("timeout_seconds", timeout.toSeconds());
            request.put("label", label);
            requests.add(request);
            String path = destination.url().replaceFirst("^https?://[^/]+", "");
            for (Map.Entry<String, PinnedHttpSender.Response> answer : answers.entrySet()) {
                if (path.startsWith(answer.getKey())) {
                    return answer.getValue();
                }
            }
            return new PinnedHttpSender.Response(404, "{\"errors\":[]}");
        }
    }

    /**
     * The Transit exchanges, request by request: what is asked of Vault for an encryption and a decryption, and
     * what the provider answers for each of Vault's replies. The Rust test replays the replies from a stub
     * server and compares the requests it receives.
     */
    private void vault(ArrayNode out) throws Exception {
        String local = standardKey(KEY_LABEL);
        String localCipher = writer(local, "vectispire-rust-reference:vault-local").encrypt("kept locally", CONTEXT);
        String plainB64 = base64("from Vault".getBytes(StandardCharsets.UTF_8));
        Object[][] scenarios = {
            // name, operation, input, context, derived answer, operation answer (status, body)
            {"encrypt under a derived key", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"ciphertext\":\"vault:v1:Y2lwaGVy\"}}"},
            {"encrypt under a key that is not derived", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":false}}", 200, "{}"},
            {"encrypt when the key cannot be read", "encrypt", "a secret", CONTEXT, 403, "{\"errors\":[\"permission denied\"]}", 200, "{}"},
            {"encrypt when the key's answer is not a boolean", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":\"true\"}}", 200, "{}"},
            {"encrypt refused by Vault", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 503, "{\"errors\":[\"sealed\"]}"},
            {"encrypt answered without a ciphertext", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{}}"},
            {"encrypt answered with a blank ciphertext", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"ciphertext\":\"  \"}}"},
            {"encrypt answered with a number", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"ciphertext\":42}}"},
            {"encrypt answered with what is not JSON", "encrypt", "a secret", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "not json"},
            {"encrypt without a context", "encrypt", "a secret", "", 200, "{\"data\":{\"derived\":false}}", 200, "{\"data\":{\"ciphertext\":\"vault:v1:bm9jdHg=\"}}"},
            {"encrypt nothing", "encrypt", "", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{}"},
            {"decrypt", "inspect", "vault:v1:Y2lwaGVy", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"plaintext\":\"" + plainB64 + "\"}}"},
            {"decrypt under a key that is not derived", "inspect", "vault:v1:Y2lwaGVy", CONTEXT, 200, "{\"data\":{\"derived\":false}}", 200, "{\"data\":{\"plaintext\":\"" + plainB64 + "\"}}"},
            {"decrypt refused", "inspect", "vault:v1:Y2lwaGVy", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 400, "{\"errors\":[\"invalid ciphertext\"]}"},
            {"decrypt answered with a blank plaintext", "inspect", "vault:v1:Y2lwaGVy", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"plaintext\":\"\"}}"},
            {"decrypt answered with what is not base64", "inspect", "vault:v1:Y2lwaGVy", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"plaintext\":\"%%%\"}}"},
            {"decrypt without a context", "inspect", "vault:v1:Y2lwaGVy", "", 200, "{\"data\":{\"derived\":true}}", 200, "{\"data\":{\"plaintext\":\"" + plainB64 + "\"}}"},
            {"a local ciphertext is read locally", "inspect", localCipher, CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{}"},
            {"a blank value is not sent", "inspect", "  ", CONTEXT, 200, "{\"data\":{\"derived\":true}}", 200, "{}"},
        };
        for (Object[] s : scenarios) {
            StubSender http = new StubSender();
            http.answers.put("/v1/transit/keys/", new PinnedHttpSender.Response((int) s[4], (String) s[5]));
            http.answers.put("/v1/transit/encrypt/", new PinnedHttpSender.Response((int) s[6], (String) s[7]));
            http.answers.put("/v1/transit/decrypt/", new PinnedHttpSender.Response((int) s[6], (String) s[7]));
            EncryptionKey key = EncryptionKey.derive(local);
            VaultKmsProvider provider = new VaultKmsProvider("http://127.0.0.1:8200//", "s.stub", " ", null, http,
                    new OutboundUrlGuard(hostname -> List.of(new byte[] {127, 0, 0, 1})), JSON,
                    new LocalKmsProvider(Optional.of(key), List.of(key)));

            ObjectNode node = out.addObject();
            node.put("name", (String) s[0]);
            node.put("operation", (String) s[1]);
            node.put("input", (String) s[2]);
            node.put("context", (String) s[3]);
            node.put("key_status", (int) s[4]);
            node.put("key_body", (String) s[5]);
            node.put("status", (int) s[6]);
            node.put("body", (String) s[7]);
            ObjectNode outcome = node.putObject("outcome");
            if (s[1].equals("encrypt")) {
                try {
                    outcome.put("cipher", provider.encrypt((String) s[2], (String) s[3]));
                } catch (RuntimeException refused) {
                    outcome.put("refused", refused.getMessage());
                }
            } else {
                putDecrypted(outcome, provider.inspect((String) s[2], (String) s[3]));
            }
            ArrayNode requests = node.putArray("requests");
            http.requests.forEach(requests::add);
        }
    }
}

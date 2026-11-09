package com.asmolabs.vectispire.core.crypto.internal;

import com.asmolabs.vectispire.common.domain.crypto.KmsProvider;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.SecretState;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * External KMS implementation using HashiCorp Vault Transit Secrets Engine.
 *
 * <p>Vault manages the master key encryption keys (KEKs) in its internal HSM/storage.
 * Secrets are encrypted/decrypted via {@code /v1/{mount}/encrypt/{keyName}} and
 * {@code /v1/{mount}/decrypt/{keyName}}, protected by {@link PinnedHttpSender} anti-SSRF checks.
 */
public class VaultKmsProvider implements KmsProvider {

    private static final Logger log = LoggerFactory.getLogger(VaultKmsProvider.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    /** What every Transit ciphertext starts with — and so what marks a stored value as encrypted. */
    public static final String CIPHERTEXT_PREFIX = "vault:";
    private static final String VAULT_PREFIX = CIPHERTEXT_PREFIX;

    private final String endpoint;
    private final String token;
    private final String keyName;
    private final String mountPath;
    private final PinnedHttpSender http;
    private final OutboundUrlGuard guard;
    private final ObjectMapper json;
    private final KmsProvider fallbackProvider;

    /** Null until Vault has answered; only a definite answer is kept. */
    private volatile Boolean derivedKey;
    private final java.util.concurrent.atomic.AtomicBoolean unboundReported = new java.util.concurrent.atomic.AtomicBoolean();

    public VaultKmsProvider(
            String endpoint,
            String token,
            String keyName,
            String mountPath,
            PinnedHttpSender http,
            OutboundUrlGuard guard,
            ObjectMapper json,
            KmsProvider fallbackProvider) {
        this.endpoint = endpoint == null ? "" : endpoint.replaceAll("/+$", "");
        this.token = token == null ? "" : token;
        this.keyName = (keyName == null || keyName.isBlank()) ? "vectispire" : keyName;
        this.mountPath = (mountPath == null || mountPath.isBlank()) ? "transit" : mountPath;
        this.http = http;
        this.guard = guard;
        this.json = json;
        this.fallbackProvider = fallbackProvider;
    }

    @Override
    public boolean isConfigured() {
        return !endpoint.isBlank() && !token.isBlank();
    }

    @Override
    public String encrypt(String plainText, String context) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }
        if (!isConfigured()) {
            throw new IllegalStateException("Vault KMS is not fully configured (missing endpoint or token).");
        }

        // **The context binds a ciphertext to its row only on a derived key.** Vault uses
        // `context` for key derivation and ignores it otherwise, silently: on an ordinary Transit
        // key the anti-relocation property SecretCipher promises — a ciphertext moved to another
        // row does not decrypt — was simply absent, with nothing to say so. So nothing is written
        // under a key that would drop it.
        if (context != null && !context.isEmpty() && !keyIsDerived()) {
            throw new IllegalStateException("Vault Transit key \"" + keyName + "\" is not a derived key, so Vault "
                    + "would ignore the context that binds each secret to its row. Create the key with derived=true "
                    + "(vault write -f " + mountPath + "/keys/" + keyName + " derived=true) and point Vectispire at it.");
        }

        String url = endpoint + "/v1/" + mountPath + "/encrypt/" + keyName;
        OutboundUrlGuard.Destination destination = guard.validateAndResolve(url, OutboundPolicy.INTERNAL_ALLOWED, "Vault KMS");

        String b64Plain = Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
        String b64Context = context == null ? "" : Base64.getEncoder().encodeToString(context.getBytes(StandardCharsets.UTF_8));

        try {
            Map<String, String> bodyMap = b64Context.isEmpty()
                    ? Map.of("plaintext", b64Plain)
                    : Map.of("plaintext", b64Plain, "context", b64Context);
            String requestBody = json.writeValueAsString(bodyMap);

            PinnedHttpSender.Response response = http.send(
                    destination,
                    Map.of("X-Vault-Token", token, "Content-Type", "application/json"),
                    requestBody,
                    TIMEOUT,
                    "Vault KMS encrypt");

            if (response.status() != 200) {
                log.error("Vault encryption request returned HTTP status {}: {}", response.status(), response.body());
                throw new IllegalStateException("Vault KMS encrypt failed with status " + response.status());
            }

            JsonNode root = json.readTree(response.body());
            JsonNode ciphertextNode = root.path("data").path("ciphertext");
            if (ciphertextNode.isMissingNode() || ciphertextNode.asText().isBlank()) {
                throw new IllegalStateException("Vault KMS response missing data.ciphertext");
            }
            return ciphertextNode.asText();
        } catch (Exception e) {
            log.error("Error communicating with Vault KMS encrypt endpoint: {}", e.getMessage());
            throw new IllegalStateException("Vault KMS encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Optional<String> decrypt(String encrypted, String context) {
        if (encrypted == null || encrypted.isBlank()) {
            return Optional.empty();
        }

        if (encrypted.startsWith(VAULT_PREFIX) && isConfigured()) {
            // Reading stays possible under a key that is not derived: refusing would lock every
            // existing deployment out of its own secrets, and Vault cannot convert a key. It is said
            // once, loudly, because the binding those ciphertexts claim is not there.
            if (context != null && !context.isEmpty() && Boolean.FALSE.equals(derivedKeyIfKnown())
                    && unboundReported.compareAndSet(false, true)) {
                log.error("Vault Transit key \"{}\" is not derived: the ciphertexts it holds are not bound to their "
                        + "rows, and one moved to another row would still decrypt. Nothing new is encrypted under it; "
                        + "re-save the secrets after switching to a key created with derived=true.", keyName);
            }
            String url = endpoint + "/v1/" + mountPath + "/decrypt/" + keyName;
            try {
                OutboundUrlGuard.Destination destination =
                        guard.validateAndResolve(url, OutboundPolicy.INTERNAL_ALLOWED, "Vault KMS");

                String b64Context = context == null ? "" : Base64.getEncoder().encodeToString(context.getBytes(StandardCharsets.UTF_8));
                Map<String, String> bodyMap = b64Context.isEmpty()
                        ? Map.of("ciphertext", encrypted)
                        : Map.of("ciphertext", encrypted, "context", b64Context);
                String requestBody = json.writeValueAsString(bodyMap);

                PinnedHttpSender.Response response = http.send(
                        destination,
                        Map.of("X-Vault-Token", token, "Content-Type", "application/json"),
                        requestBody,
                        TIMEOUT,
                        "Vault KMS decrypt");

                if (response.status() == 200) {
                    JsonNode root = json.readTree(response.body());
                    JsonNode plaintextNode = root.path("data").path("plaintext");
                    if (!plaintextNode.isMissingNode() && !plaintextNode.asText().isBlank()) {
                        byte[] decoded = Base64.getDecoder().decode(plaintextNode.asText());
                        return Optional.of(new String(decoded, StandardCharsets.UTF_8));
                    }
                }
                log.warn("Vault decrypt returned status {}: {}", response.status(), response.body());
            } catch (Exception e) {
                log.warn("Vault KMS decryption failed: {}", e.getMessage());
            }
        }

        // Fallback for previous local keys or non-vault ciphertexts
        if (fallbackProvider != null) {
            return fallbackProvider.decrypt(encrypted, context);
        }
        return Optional.empty();
    }

    /** Whether the Transit key derives per context, asked of Vault once. */
    private boolean keyIsDerived() {
        Boolean known = derivedKeyIfKnown();
        if (known == null) {
            throw new IllegalStateException("Vault KMS: could not read the Transit key \"" + keyName
                    + "\" to check that it is derived.");
        }
        return known;
    }

    private Boolean derivedKeyIfKnown() {
        if (derivedKey != null || !isConfigured()) {
            return derivedKey;
        }
        try {
            OutboundUrlGuard.Destination destination = guard.validateAndResolve(
                    endpoint + "/v1/" + mountPath + "/keys/" + keyName, OutboundPolicy.INTERNAL_ALLOWED, "Vault KMS");
            PinnedHttpSender.Response response =
                    http.send(destination, Map.of("X-Vault-Token", token), null, TIMEOUT, "Vault KMS key");
            if (response.status() == 200) {
                JsonNode derived = json.readTree(response.body()).path("data").path("derived");
                if (derived.isBoolean()) {
                    derivedKey = derived.asBoolean();
                }
            } else {
                log.warn("Vault KMS: reading key \"{}\" returned HTTP {}.", keyName, response.status());
            }
        } catch (Exception unreadable) {
            log.warn("Vault KMS: could not read key \"{}\": {}", keyName, unreadable.getMessage());
        }
        return derivedKey;
    }

    @Override
    public Decrypted inspect(String encrypted, String context) {
        if (encrypted == null || encrypted.isBlank()) {
            return new Decrypted("", SecretState.UNREADABLE);
        }

        if (encrypted.startsWith(VAULT_PREFIX)) {
            Optional<String> decrypted = decrypt(encrypted, context);
            return decrypted.map(s -> new Decrypted(s, SecretState.CURRENT))
                    .orElseGet(() -> new Decrypted("", SecretState.UNREADABLE));
        }

        if (fallbackProvider != null) {
            return fallbackProvider.inspect(encrypted, context);
        }
        return new Decrypted("", SecretState.UNREADABLE);
    }
}

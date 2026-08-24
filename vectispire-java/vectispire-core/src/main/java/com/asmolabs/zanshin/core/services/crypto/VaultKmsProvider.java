package com.asmolabs.zanshin.core.services.crypto;

import com.asmolabs.zanshin.common.domain.crypto.KmsProvider;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.SecretState;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.asmolabs.zanshin.core.services.PinnedHttpSender;
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
    private static final String VAULT_PREFIX = "vault:";

    private final String endpoint;
    private final String token;
    private final String keyName;
    private final String mountPath;
    private final PinnedHttpSender http;
    private final OutboundUrlGuard guard;
    private final ObjectMapper json;
    private final KmsProvider fallbackProvider;

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
        this.keyName = (keyName == null || keyName.isBlank()) ? "zanshin" : keyName;
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

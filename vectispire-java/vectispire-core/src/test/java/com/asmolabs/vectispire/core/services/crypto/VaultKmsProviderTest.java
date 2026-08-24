package com.asmolabs.vectispire.core.services.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.LocalKmsProvider;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.SecretState;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.core.services.PinnedHttpSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Vault KMS Provider")
class VaultKmsProviderTest {

    private static class TestHttpSender extends PinnedHttpSender {
        PinnedHttpSender.Response nextResponse = new PinnedHttpSender.Response(200, "{}");

        @Override
        public Response send(
                OutboundUrlGuard.Destination destination,
                Map<String, String> headers,
                String body,
                Duration timeout,
                String label) {
            return nextResponse;
        }
    }

    private TestHttpSender http;
    private OutboundUrlGuard guard;
    private ObjectMapper json;
    private LocalKmsProvider fallback;
    private VaultKmsProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        http = new TestHttpSender();
        guard = new OutboundUrlGuard(hostname -> List.of(new byte[] {127, 0, 0, 1}));
        json = new ObjectMapper();

        EncryptionKey key = EncryptionKey.derive(EncryptionKey.generate());
        fallback = new LocalKmsProvider(Optional.of(key), List.of(key));

        provider = new VaultKmsProvider(
                "http://127.0.0.1:8200",
                "vault-token-xyz",
                "vectispire",
                "transit",
                http,
                guard,
                json,
                fallback);
    }

    @Test
    @DisplayName("encrypts via Vault Transit endpoint")
    void encryptsViaVault() {
        String vaultResponse = "{\"data\": {\"ciphertext\": \"vault:v1:8d7f6e5a4b3c\"}}";
        http.nextResponse = new PinnedHttpSender.Response(200, vaultResponse);

        String encrypted = provider.encrypt("my-secret-token", "ctx:1");
        assertThat(encrypted).isEqualTo("vault:v1:8d7f6e5a4b3c");
    }

    @Test
    @DisplayName("decrypts via Vault Transit endpoint")
    void decryptsViaVault() {
        String plain = "decrypted-content";
        String b64Plain = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        String vaultResponse = "{\"data\": {\"plaintext\": \"" + b64Plain + "\"}}";
        http.nextResponse = new PinnedHttpSender.Response(200, vaultResponse);

        Optional<String> result = provider.decrypt("vault:v1:8d7f6e5a4b3c", "ctx:1");
        assertThat(result).contains(plain);

        Decrypted inspected = provider.inspect("vault:v1:8d7f6e5a4b3c", "ctx:1");
        assertThat(inspected.plainText()).isEqualTo(plain);
        assertThat(inspected.state()).isEqualTo(SecretState.CURRENT);
    }

    @Test
    @DisplayName("falls back to local keys for legacy or non-vault ciphertexts")
    void fallsBackToLocalKeys() {
        String localEncrypted = fallback.encrypt("legacy-secret", "ctx:legacy");
        Optional<String> decrypted = provider.decrypt(localEncrypted, "ctx:legacy");
        assertThat(decrypted).contains("legacy-secret");
    }
}


package com.asmolabs.zanshin.core.services.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.crypto.EncryptionKey;
import com.asmolabs.zanshin.common.domain.crypto.LocalKmsProvider;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.SecretState;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.asmolabs.zanshin.core.services.PinnedHttpSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Vault KMS Provider")
class VaultKmsProviderTest {

    private PinnedHttpSender http;
    private OutboundUrlGuard guard;
    private ObjectMapper json;
    private LocalKmsProvider fallback;
    private VaultKmsProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        http = mock(PinnedHttpSender.class);
        guard = mock(OutboundUrlGuard.class);
        json = new ObjectMapper();

        EncryptionKey key = EncryptionKey.derive("bWFzdGVyLWtleS0zMi1ieXRlcy1sb25nLXNlY3JldC0xMQ==");
        fallback = new LocalKmsProvider(Optional.of(key), List.of(key));

        provider = new VaultKmsProvider(
                "http://127.0.0.1:8200",
                "vault-token-xyz",
                "zanshin",
                "transit",
                http,
                guard,
                json,
                fallback);

        OutboundUrlGuard.Destination dummyDest = new OutboundUrlGuard.Destination(
                "http://127.0.0.1:8200",
                "127.0.0.1",
                List.of(InetAddress.getByName("127.0.0.1")));
        when(guard.validateAndResolve(any(), eq(OutboundPolicy.INTERNAL_ALLOWED), any())).thenReturn(dummyDest);
    }

    @Test
    @DisplayName("encrypts via Vault Transit endpoint")
    void encryptsViaVault() {
        String vaultResponse = "{\"data\": {\"ciphertext\": \"vault:v1:8d7f6e5a4b3c\"}}";
        when(http.send(any(), any(), any(), any(), eq("Vault KMS encrypt")))
                .thenReturn(new PinnedHttpSender.Response(200, vaultResponse));

        String encrypted = provider.encrypt("my-secret-token", "ctx:1");
        assertThat(encrypted).isEqualTo("vault:v1:8d7f6e5a4b3c");
    }

    @Test
    @DisplayName("decrypts via Vault Transit endpoint")
    void decryptsViaVault() {
        String plain = "decrypted-content";
        String b64Plain = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        String vaultResponse = "{\"data\": {\"plaintext\": \"" + b64Plain + "\"}}";

        when(http.send(any(), any(), any(), any(), eq("Vault KMS decrypt")))
                .thenReturn(new PinnedHttpSender.Response(200, vaultResponse));

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

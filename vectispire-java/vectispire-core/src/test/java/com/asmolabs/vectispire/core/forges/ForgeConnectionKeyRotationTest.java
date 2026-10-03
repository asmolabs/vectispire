package com.asmolabs.vectispire.core.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties;
import com.asmolabs.vectispire.core.forges.internal.ForgeProbes;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * An {@code ENCRYPTION_KEY} rotation reaches the forge connections (decision 0037 §2, {@code KEY_ROTATION.md}):
 * the list says {@code previous_key} while a token is still sealed under the old key, and saving the
 * connection re-seals it under the new one — without presenting it to the forge, which a renaming does not do.
 *
 * <p>The ciphers are real; the row lives in a map rather than a database, because what is pinned is which
 * key sealed it, not how it is stored.
 */
@DisplayName("a key rotation reaches the forge connections")
class ForgeConnectionKeyRotationTest {

    private static final String TOKEN = "glpat-Rotation000000000000000"; // gitleaks:allow

    @Test
    @DisplayName("a token sealed under the previous key is listed as such, and re-sealed under the current one when saved")
    void savingReseals() {
        String oldKey = EncryptionKey.generate();
        String newKey = EncryptionKey.generate();
        EncryptionService before = new EncryptionService(new EncryptionProperties(Optional.of(oldKey), List.of()));
        EncryptionService during = new EncryptionService(new EncryptionProperties(Optional.of(newKey), List.of(oldKey)));
        EncryptionService after = new EncryptionService(new EncryptionProperties(Optional.of(newKey), List.of()));

        UUID id = UUID.randomUUID();
        String context = SecretCipher.forgeConnectionContext(id.toString());
        ForgeConnectionEntity row = row(id, before.encrypt(TOKEN, context));
        ForgeConnectionRepository connections = mock(ForgeConnectionRepository.class);
        when(connections.findById(id)).thenReturn(Optional.of(row));
        when(connections.findAllByOrderByNameAsc()).thenReturn(List.of(row));
        when(connections.saveAndFlush(any())).thenAnswer(saved -> saved.getArgument(0));
        ForgeProbes probes = mock(ForgeProbes.class);
        ForgeConnectionService service = new ForgeConnectionService(connections,
                mock(ForgeDiscoveryRepository.class), mock(ForgeRepositoryRepository.class),
                mock(ForgeImportLinkRepository.class), probes, during,
                mock(AuditLogService.class), Clock.systemUTC(), mock(PlatformTransactionManager.class));

        assertThat(service.list()).singleElement()
                .satisfies(view -> assertThat(view.encryptionState()).isEqualTo("previous_key"));

        ForgeConnectionView saved = service.update(id, new ForgeConnectionService.Change("GitLab", null, null),
                new RequestActor("admin", "127.0.0.1", null));

        assertThat(saved.encryptionState()).isEqualTo("current");
        assertThat(after.inspect(row.getToken(), context).plainText()).isEqualTo(TOKEN);
        verifyNoInteractions(probes);
    }

    private static ForgeConnectionEntity row(UUID id, String ciphertext) {
        ForgeConnectionEntity row = new ForgeConnectionEntity();
        Instant now = Instant.now();
        row.setId(id);
        row.setName("Internal GitLab");
        row.setKind("gitlab");
        row.setEdition("gitlab_self_managed");
        row.setBaseUrl("https://gitlab.example.org");
        row.setInternalNetwork(true);
        row.setToken(ciphertext);
        row.setCredentialKind("gitlab_bot");
        row.setScopes("read_api");
        row.setCanWrite(false);
        row.setProbedAt(now);
        row.setCreatedAt(now);
        row.setCreatedBy("admin");
        row.setUpdatedAt(now);
        row.setUpdatedBy("admin");
        return row;
    }
}

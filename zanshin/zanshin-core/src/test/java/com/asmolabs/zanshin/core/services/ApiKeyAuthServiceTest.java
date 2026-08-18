package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.zanshin.common.domain.apikeys.ApiKeys;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.core.persistence.ApiKeyEntity;
import com.asmolabs.zanshin.core.repositories.Agents;
import com.asmolabs.zanshin.core.repositories.ApiKeysRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("authenticating an API key")
class ApiKeyAuthServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T10:00:00Z");

    private ApiKeysRepository keys;
    private ApiKeyAuthService service;
    private ApiKeys.IssuedKey issued;

    @BeforeEach
    void wire() {
        keys = mock(ApiKeysRepository.class);
        service = new ApiKeyAuthService(keys, mock(Agents.class), Clock.fixed(NOW, ZoneOffset.UTC));
        issued = ApiKeys.generate();
        when(keys.findByPrefix(anyString())).thenReturn(List.of());
    }

    @Test
    @DisplayName("only the keys sharing the prefix are hashed against")
    void thePrefixNarrowsTheCandidates() {
        when(keys.findByPrefix(issued.prefix())).thenReturn(List.of(key(null)));

        assertThat(service.resolve(issued.fullKey())).isPresent();
        // Without the prefix, every request would cost one verification per existing key — a
        // denial of service offered to whoever presents anything at all.
        verify(keys).findByPrefix(issued.prefix());
    }

    @Test
    void marksTheKeyAsUsed() {
        ApiKeyEntity stored = key(null);
        when(keys.findByPrefix(issued.prefix())).thenReturn(List.of(stored));

        service.resolve(issued.fullKey());

        verify(keys).markUsed(stored.getId(), NOW);
    }

    @Test
    @DisplayName("an expired key is refused, and looks exactly like an unknown one")
    void expiredAndUnknownAreIndistinguishable() {
        when(keys.findByPrefix(issued.prefix())).thenReturn(List.of(key(NOW.minusSeconds(1))));

        assertThat(service.resolve(issued.fullKey())).isEmpty();
        assertThat(service.resolve(ApiKeys.generate().fullKey())).isEmpty();
        // Telling the two apart tells whoever is probing which half of a guess was right.
        verify(keys, never()).markUsed(any(), any());
    }

    @Test
    @DisplayName("a key of the right prefix but the wrong body is refused")
    void aWrongBodyDoesNotPass() {
        when(keys.findByPrefix(anyString())).thenReturn(List.of(key(null)));

        assertThat(service.resolve(issued.prefix() + "-not-the-right-body")).isEmpty();
    }

    @Test
    void refusesSomethingTooShortToBeAKey() {
        assertThat(service.resolve("zsk")).isEmpty();
        assertThat(service.resolve(null)).isEmpty();
        verify(keys, never()).findByPrefix(anyString());
    }

    @Test
    void readsTheScopesItCarries() {
        ApiKeyEntity stored = key(null);
        stored.setScopes(" scan , read ");

        assertThat(service.hasScope(stored, ApiKeyScope.SCAN)).isTrue();
        assertThat(service.hasScope(stored, ApiKeyScope.AGENT)).isFalse();
    }

    private ApiKeyEntity key(Instant expiresAt) {
        ApiKeyEntity stored = new ApiKeyEntity();
        stored.setId(UUID.randomUUID());
        stored.setName("agent");
        stored.setPrefix(issued.prefix());
        stored.setKeyHash(PasswordHasher.hash(issued.fullKey()));
        stored.setExpiresAt(expiresAt);
        stored.setCreatedAt(NOW.minusSeconds(3600));
        return stored;
    }
}

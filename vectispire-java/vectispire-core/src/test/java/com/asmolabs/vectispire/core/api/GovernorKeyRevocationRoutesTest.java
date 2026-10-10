package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * A platform governor's key is administered by a governor, as its account is (the audit of 10 October 2026):
 * an administrator could not reset a governor's password, and could still revoke the key its pipeline uses.
 */
@DisplayName("revoking a platform governor's key")
class GovernorKeyRevocationRoutesTest extends ApiTestBase {

    @Autowired
    private UserRepository users;

    @Autowired
    private ApiKeyRepository keys;

    @Test
    @DisplayName("is refused to an administrator, and the key stays")
    void anAdministratorCannot() throws Exception {
        UUID key = keyOf("governor-" + System.nanoTime());
        String admin = tokenFor("admin-" + System.nanoTime(), Role.ADMIN, false);

        mvc.perform(authenticated(delete("/api/v1/api-keys/" + key), admin)).andExpect(status().isBadRequest());

        assertThat(keys.findById(key)).isPresent();
    }

    @Test
    @DisplayName("is allowed to a governor")
    void aGovernorCan() throws Exception {
        UUID key = keyOf("governor-" + System.nanoTime());
        String governor = tokenFor("other-governor-" + System.nanoTime(), Role.SUPERUSER, false);

        mvc.perform(authenticated(delete("/api/v1/api-keys/" + key), governor)).andExpect(status().isNoContent());

        assertThat(keys.findById(key)).isEmpty();
    }

    private UUID keyOf(String governorName) throws Exception {
        tokenFor(governorName, Role.SUPERUSER, false);
        ApiKeyEntity key = new ApiKeyEntity();
        String salt = UUID.randomUUID().toString();
        key.setName("governor pipeline");
        key.setKeyHash("invented-hash-" + salt);
        key.setPrefix("vsp_" + salt.substring(0, 4));
        key.setCreatedAt(Instant.now());
        key.setScopes("read");
        key.setOwnerUserId(users.findByUsername(governorName).orElseThrow().getId());
        return keys.save(key).getId();
    }
}

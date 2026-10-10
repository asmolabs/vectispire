package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Changing one's own password takes the account's integration keys with it.
 *
 * <p>The audit of 10 October 2026: the other sessions closed and the keys stayed. A key minted by
 * whoever held the password acts for the account whatever the password becomes, so the intruder
 * kept reading and exporting through it — the gap an administrator's reset had already closed.
 */
@DisplayName("changing one's own password")
class PasswordChangeRevokesKeysRoutesTest extends ApiTestBase {

    @Autowired
    private UserRepository users;

    @Autowired
    private ApiKeyRepository keys;

    @Autowired
    private AuditLogRepository auditLog;

    @Test
    @DisplayName("revokes the keys the account issued, says how many, and audits each one")
    void revokesTheAccountsKeys() throws Exception {
        String username = "rotating-" + System.nanoTime();
        // An administrator: only they issue keys, and theirs are the ones worth phishing for.
        String session = tokenFor(username, Role.ADMIN, false);
        long id = users.findByUsername(username).orElseThrow().getId();
        mvc.perform(authenticated(post("/api/v1/api-keys"), session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "minted-with-the-old-password", "scopes", List.of("read")))))
                .andExpect(status().isOk());
        assertThat(keys.findByOwnerUserId(id)).hasSize(1);

        mvc.perform(authenticated(post("/api/v1/auth/change-password"), session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "current_password", "correct horse battery staple",
                                "new_password", "a brand new passphrase for this one"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedApiKeys").value(1));

        assertThat(keys.findByOwnerUserId(id)).isEmpty();
        assertThat(auditLog.findAll())
                .filteredOn(entry -> AuditOperation.API_KEY_DELETED.wireName().equals(entry.getOperationType()))
                .extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description)
                        .contains("minted-with-the-old-password")
                        .contains("password change"));
    }
}

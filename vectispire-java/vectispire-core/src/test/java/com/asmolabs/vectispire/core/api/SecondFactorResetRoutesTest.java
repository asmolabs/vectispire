package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Clearing another account's second factor, {@code DELETE /api/v1/users/{id}/second-factor}.
 *
 * <p>An owner locked out of their own factor — a lost phone, or a factor somebody else enrolled with a
 * session of theirs — had no way back but the database: disabling asks for a current code. The route is
 * an administrator's, never for their own account, and under the governor's rules as a password reset is.
 */
@DisplayName("resetting an account's second factor")
class SecondFactorResetRoutesTest extends ApiTestBase {

    private static final String PATH = "/api/v1/users/%d/second-factor";

    @Autowired
    private UserRepository users;

    @Autowired
    private AuditLogRepository auditEntries;

    @Test
    @DisplayName("an administrator clears it, the account's sessions close, and the entry names both")
    void anAdministratorClearsIt() throws Exception {
        String admin = tokenFor("mfa-resetting-admin", Role.ADMIN, false);
        String session = tokenFor("mfa-locked-out", Role.USER, false);
        UserEntity account = enrolled("mfa-locked-out");

        mvc.perform(authenticated(delete(PATH.formatted(account.getId())), admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaEnabled").value(false))
                .andExpect(jsonPath("$.activeSessions").value(0));

        UserEntity cleared = users.findById(account.getId()).orElseThrow();
        assertThat(cleared.getMfaEnabled()).isFalse();
        assertThat(cleared.getTotpSecret()).isNull();
        assertThat(cleared.getMfaBackupCodes()).isNull();
        mvc.perform(authenticated(get("/api/v1/auth/me"), session)).andExpect(status().isUnauthorized());
        assertThat(auditEntries.findAll()).filteredOn(entry -> String.valueOf(account.getId()).equals(entry.getResourceId()))
                .filteredOn(entry -> AuditOperation.USER_UPDATED.wireName().equals(entry.getOperationType()))
                .singleElement()
                .satisfies(entry -> {
                    assertThat(entry.getUserId()).isEqualTo("mfa-resetting-admin");
                    assertThat(entry.getDescription()).contains("mfa-locked-out").contains("second factor reset");
                });
    }

    @Test
    @DisplayName("every role that does not administer accounts is refused 403, and the factor stays")
    void nonAdministratorsAreRefused() throws Exception {
        tokenFor("mfa-refused-target", Role.USER, false);
        UserEntity account = enrolled("mfa-refused-target");

        for (String token : List.of(asReader(), asAuditor(), asCiso(), asSecurityChampion())) {
            mvc.perform(authenticated(delete(PATH.formatted(account.getId())), token))
                    .andExpect(status().isForbidden());
        }
        assertThat(users.findById(account.getId()).orElseThrow().getMfaEnabled()).isTrue();
    }

    @Test
    @DisplayName("an administrator cannot clear their own")
    void notOnesOwn() throws Exception {
        String admin = tokenFor("mfa-own-admin", Role.ADMIN, false);
        UserEntity self = enrolled("mfa-own-admin");

        MvcResult refused = mvc.perform(authenticated(delete(PATH.formatted(self.getId())), admin))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).contains("your own second factor");
        assertThat(users.findById(self.getId()).orElseThrow().getMfaEnabled()).isTrue();
    }

    @Test
    @DisplayName("a platform governor's is cleared by a governor only")
    void aGovernorsIsTheGovernors() throws Exception {
        tokenFor("mfa-governor", Role.SUPERUSER, false);
        UserEntity governor = enrolled("mfa-governor");

        MvcResult refused = mvc.perform(authenticated(delete(PATH.formatted(governor.getId())), asAdmin()))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).contains("Only a platform governor");
        assertThat(users.findById(governor.getId()).orElseThrow().getMfaEnabled()).isTrue();

        String otherGovernor = tokenFor("mfa-resetting-governor", Role.SUPERUSER, false);
        mvc.perform(authenticated(delete(PATH.formatted(governor.getId())), otherGovernor))
                .andExpect(status().isOk());
        assertThat(users.findById(governor.getId()).orElseThrow().getMfaEnabled()).isFalse();
    }

    private UserEntity enrolled(String username) {
        UserEntity account = users.findByUsername(username).orElseThrow();
        account.setMfaEnabled(true);
        account.setTotpSecret("sealed-secret-placeholder");
        account.setMfaBackupCodes("sealed-codes-placeholder");
        return users.save(account);
    }
}

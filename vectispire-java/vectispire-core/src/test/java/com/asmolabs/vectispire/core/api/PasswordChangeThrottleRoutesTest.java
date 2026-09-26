package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.LoginThrottle;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.core.access.TotpService;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.access.web.AuthController;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Proofs of identity asked of a signed-in account, over HTTP.
 *
 * <p>A session is not a licence to guess the secrets behind it. The current password asked by
 * {@code /auth/change-password} was checked with no ceiling and no trace, so a workstation left
 * unlocked was a password oracle at whatever rate the server sustained. And a code presented after
 * an administrator deactivated the account still opened a session.
 */
@DisplayName("proofs of identity on a signed-in account")
class PasswordChangeThrottleRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private UserRepository users;

    @Autowired
    private TotpService totp;

    @Autowired
    private java.time.Clock clock;

    @Test
    @DisplayName("wrong current passwords spend the sign-in budget, are recorded, and lock with a Retry-After")
    void aWrongCurrentPasswordCounts() throws Exception {
        String username = "changer-" + System.nanoTime();
        String session = tokenFor(username, Role.USER, false);
        String wrong = write(Map.of("current_password", "not it", "new_password", "a brand new passphrase"));

        for (int attempt = 0; attempt < LoginThrottle.MAX_ATTEMPTS_PER_USER; attempt++) {
            mvc.perform(authenticated(post("/api/v1/auth/change-password"), session)
                            .contentType(MediaType.APPLICATION_JSON).content(wrong))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(authenticated(post("/api/v1/auth/change-password"), session)
                        .contentType(MediaType.APPLICATION_JSON).content(wrong))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));

        assertThat(auditLog.findAll())
                .filteredOn(entry -> username.equals(entry.getUserId()))
                .extracting(AuditLogEntity::getOperationType)
                .containsOnly(AuditOperation.LOGIN_FAILURE.wireName(), AuditOperation.LOGIN_BLOCKED.wireName())
                .hasSize(LoginThrottle.MAX_ATTEMPTS_PER_USER + 1);

        // One budget: the sign-in form is locked for this account too, right password included.
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.LoginRequest(username, PASSWORD))))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("a code presented after the account was deactivated opens no session")
    void aDeactivatedAccountIsRefusedAtTheCode() throws Exception {
        UserEntity user = new UserEntity();
        user.setUsername("mfa-deactivated-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash(PASSWORD));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setMfaEnabled(false);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        UserEntity saved = users.save(user);
        // Enrolled for real, so the code presented below is a right one: only the deactivation
        // can refuse it.
        String secret = Totp.generateSecret();
        String backup = totp.enable(UserView.of(saved), secret, Totp.generateCode(secret, clock.instant()))
                .backupCodes().getFirst();
        saved = users.findById(saved.getId()).orElseThrow();

        String response = mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.LoginRequest(saved.getUsername(), PASSWORD))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String challenge = json.readTree(response).get("mfa_token").asText();

        saved.setIsActive(false);
        users.save(saved);

        mvc.perform(post("/api/v1/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.MfaVerifyRequest(challenge, backup))))
                .andExpect(status().isUnauthorized());
        // The challenge went with the refusal: reactivating the account does not revive it.
        saved.setIsActive(true);
        users.save(saved);
        String again = mvc.perform(post("/api/v1/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(new AuthController.MfaVerifyRequest(challenge, backup))))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getErrorMessage();
        assertThat(again).contains("expired or is invalid");
    }
}

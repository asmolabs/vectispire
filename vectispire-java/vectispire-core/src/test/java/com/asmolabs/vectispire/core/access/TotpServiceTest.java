package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The second factor against the database: what one code, or one backup code, may open.
 *
 * <p>Each check used to be a read, a comparison in Java and nothing recorded — so a code stayed
 * good for its whole window and a backup code could be spent by two sign-ins at once. Both are
 * now decided by an update, and the tests below hold two copies of the account where a race
 * would.
 */
@DisplayName("TOTP verification")
class TotpServiceTest extends VectispireContextTest {

    @Autowired
    private TotpService totp;

    @Autowired
    private UserRepository users;

    @Autowired
    private Clock clock;

    /**
     * {@code at} is the instant the enrolment code was generated for. A test that needs "the same
     * window" reads it rather than the clock again: two readings straddle a 30-second step often
     * enough to fail a run in CI, and the second then names the next window's code, which was
     * never spent.
     */
    private record Enrolled(UserEntity user, String secret, List<String> backupCodes, Instant at) {}

    private Enrolled enrolled() {
        Instant now = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername("totp-" + System.nanoTime());
        user.setPassword(PasswordHasher.hash("correct horse battery staple"));
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        user = users.save(user);

        String secret = totp.setup(UserView.of(user)).secret();
        List<String> codes = totp.enable(UserView.of(user), "correct horse battery staple", secret, Totp.generateCode(secret, now), "127.0.0.1", null).backupCodes();
        return new Enrolled(users.findById(user.getId()).orElseThrow(), secret, codes, now);
    }

    /**
     * The counts the compliance report's identity ceiling reads without a provider. Read as differences,
     * since the other tests of this context leave accounts behind.
     */
    @Test
    @DisplayName("counts the active password accounts, and those of them with no second factor")
    void enrolmentCountsWhatSignInDemands() {
        TotpService.Enrolment before = totp.enrolment();

        enrolled();
        account(true, true);
        account(false, true);
        account(true, false);

        TotpService.Enrolment after = totp.enrolment();
        assertThat(after.passwordAccounts() - before.passwordAccounts())
                .as("the enrolled account and the one without TOTP; neither the deactivated one nor the one with no password")
                .isEqualTo(2);
        assertThat(after.withoutSecondFactor() - before.withoutSecondFactor())
                .as("the active password account without TOTP alone")
                .isEqualTo(1);
    }

    private void account(boolean active, boolean withPassword) {
        Instant now = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername("no-totp-" + System.nanoTime());
        user.setPassword(withPassword ? PasswordHasher.hash("correct horse battery staple") : null);
        user.setRole(Role.USER.name());
        user.setIsActive(active);
        user.setMustChangePassword(false);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        users.save(user);
    }

    @Test
    @DisplayName("a code opens once: presented again inside its window, it is refused")
    void aCodeIsNotReplayed() {
        Enrolled account = enrolled();
        String next = Totp.generateCode(account.secret(), account.at().plusSeconds(30));

        assertThat(totp.verify(account.user(), next)).isTrue();
        assertThat(totp.verify(users.findById(account.user().getId()).orElseThrow(), next)).isFalse();
    }

    @Test
    @DisplayName("the code that proved the enrolment opens no sign-in afterwards")
    void theEnrolmentCodeIsSpent() {
        Enrolled account = enrolled();

        assertThat(totp.verify(account.user(), Totp.generateCode(account.secret(), account.at()))).isFalse();
    }

    @Test
    @DisplayName("a backup code spent through one copy of the account is refused through another")
    void aBackupCodeIsSpentOnce() {
        Enrolled account = enrolled();
        // Two sign-ins racing each hold the account as it was read: the same ciphertext, the
        // same code inside it.
        UserEntity first = users.findById(account.user().getId()).orElseThrow();
        UserEntity second = users.findById(account.user().getId()).orElseThrow();
        String code = account.backupCodes().getFirst();

        assertThat(totp.verify(first, code)).isTrue();
        assertThat(totp.verify(second, code)).isFalse();
        // And the others are still there: the refusal spent nothing.
        assertThat(totp.verify(users.findById(account.user().getId()).orElseThrow(), account.backupCodes().get(1)))
                .isTrue();
    }

    @Test
    @DisplayName("enrolling over an active factor is refused: replacing it goes through disabling it")
    void anActiveFactorIsNotOverwritten() {
        Enrolled account = enrolled();
        String attacker = totp.setup(UserView.of(account.user())).secret();

        assertThatThrownBy(() -> totp.enable(UserView.of(account.user()), "correct horse battery staple", attacker, Totp.generateCode(attacker, clock.instant()), "127.0.0.1", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already enabled");
        assertThat(totp.verify(account.user(), Totp.generateCode(account.secret(), account.at().plusSeconds(30))))
                .isTrue();
    }

    @Autowired
    private com.asmolabs.vectispire.core.audit.AuditLogService audit;

    @Autowired
    private AuthService auth;

    @org.springframework.beans.factory.annotation.Value("${vectispire.encryption.key}")
    private String currentPassphrase;

    @Test
    @DisplayName("a secret and backup codes sealed under a previous key are re-sealed at the next check")
    void aRotatedSecondFactorIsResealed() {
        // Read at sign-in and written only at enrolment, they stayed under the old key for good, and
        // removing it refused the second factor of every enrolled account.
        Enrolled enrolled = enrolled();
        EncryptionService rotatedKeys = new EncryptionService(new com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties(
                java.util.Optional.of("totp-rotation-new-passphrase-0123456789"), List.of(currentPassphrase)));
        TotpService rotated = new TotpService(users, rotatedKeys, audit, clock, auth);
        long id = enrolled.user().getId();
        assertThat(rotatedKeys.sealOf(enrolled.user().getTotpSecret(), "user:totp_secret:" + id))
                .isEqualTo(EncryptionService.Seal.PREVIOUS_KEY);

        // A wrong code: the account is moved all the same, by whoever reaches the check.
        assertThat(rotated.verify(users.findById(id).orElseThrow(), "000000x")).isFalse();

        UserEntity after = users.findById(id).orElseThrow();
        assertThat(rotatedKeys.sealOf(after.getTotpSecret(), "user:totp_secret:" + id)).isEqualTo(EncryptionService.Seal.CURRENT);
        assertThat(rotatedKeys.inspect(after.getTotpSecret(), "user:totp_secret:" + id).plainText()).isEqualTo(enrolled.secret());
        assertThat(rotatedKeys.sealOf(after.getMfaBackupCodes(), "user:backup_codes:" + id)).isEqualTo(EncryptionService.Seal.CURRENT);
        // And a backup code still opens it, under the new key alone.
        TotpService newKeyOnly = new TotpService(users, new EncryptionService(new com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties(
                java.util.Optional.of("totp-rotation-new-passphrase-0123456789"), List.of())), audit, clock, auth);
        assertThat(newKeyOnly.verify(after, enrolled.backupCodes().getFirst())).isTrue();
    }
}

package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.SealedStore;
import com.asmolabs.vectispire.core.crypto.StoreCensus;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.OptionalLong;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * TOTP multi-factor authentication enrolment, verification and emergency recovery.
 */
@Service
public class TotpService implements SealedStore {

    private static final String TOTP_CONTEXT = "user:totp_secret";
    private static final String BACKUP_CONTEXT = "user:backup_codes";

    private final UserRepository users;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;
    private final AuthService auth;

    public TotpService(UserRepository users, EncryptionService encryption, AuditLogService audit, Clock clock, AuthService auth) {
        this.users = users;
        this.encryption = encryption;
        this.audit = audit;
        this.clock = clock;
        this.auth = auth;
    }

    /** The account has used up its wrong codes for this window; the caller answers 429. */
    public static class SecondFactorLockedException extends RuntimeException {
        private final java.time.Duration retryAfter;

        public SecondFactorLockedException(java.time.Duration retryAfter) {
            super("Too many wrong verification codes. Try again later.");
            this.retryAfter = retryAfter;
        }

        public java.time.Duration retryAfter() {
            return retryAfter;
        }
    }

    /** Enrolment's password was wrong; the caller answers 401, as the password change does. */
    public static class CurrentPasswordWrongException extends RuntimeException {
        public CurrentPasswordWrongException() {
            super("Current password is incorrect.");
        }
    }

    /** The account's password budget is spent; the caller answers 429. */
    public static class PasswordLockedException extends RuntimeException {
        private final java.time.Duration retryAfter;

        public PasswordLockedException(java.time.Duration retryAfter) {
            super("Too many wrong passwords. Try again later.");
            this.retryAfter = retryAfter;
        }

        public java.time.Duration retryAfter() {
            return retryAfter;
        }
    }

    public record SetupResponse(String secret, String qrCodeUri, String issuer) {}

    public record EnableResponse(boolean success, List<String> backupCodes) {}

    /**
     * @param passwordAccounts the active accounts holding a local password
     * @param withoutSecondFactor of those, the ones with no TOTP enrolled
     */
    public record Enrolment(long passwordAccounts, long withoutSecondFactor) {}

    /**
     * How far the local second factor reaches — what the compliance report's identity ceiling reads
     * when no provider is configured. Two statements, which READ COMMITTED does not read from one
     * snapshot: an account created between them is clamped out rather than reported as "3 of 2".
     */
    @Transactional(readOnly = true)
    public Enrolment enrolment() {
        long accounts = users.countActiveWithPassword();
        return new Enrolment(accounts, Math.min(accounts, users.countActiveWithPasswordAndNoSecondFactor()));
    }

    public SetupResponse setup(UserView user) {
        String secret = Totp.generateSecret();
        String issuer = "Vectispire";
        String qrUri = Totp.qrCodeUri(user.username(), secret, issuer);
        return new SetupResponse(secret, qrUri, issuer);
    }

    /**
     * The row is read here, by the account's id: the caller holds a {@link UserView}, which carries
     * no secret and is not something to save.
     *
     * <p><b>The password first.</b> Enrolling with a session alone let whoever held one — stolen, or
     * left open on a desk — put the account's second factor on their own phone, and the owner, who
     * had no code to disable it with, was out until somebody edited the database. A wrong password
     * spends the account's sign-in budget and is recorded, as at the password change, so the route is
     * no way to guess it either.
     *
     * @throws java.util.NoSuchElementException when the account is gone — only a deletion racing
     *     this request, which the bearer filter found active
     * @throws CurrentPasswordWrongException when the password is not the account's
     * @throws PasswordLockedException when the account's sign-in budget is spent
     */
    public EnableResponse enable(
            UserView account, String password, String secret, String code, String ipAddress, String userAgent) {
        UserEntity user = users.findById(account.id()).orElseThrow();
        AuthService.Reservation attempt = auth.reservePassword(user.getId(), ipAddress);
        if (!attempt.admitted()) {
            audit.record(new AuditLogService.Record(
                    AuditOperation.LOGIN_BLOCKED,
                    String.valueOf(user.getId()),
                    "MFA enrolment refused by the throttle (" + attempt.retryAfter().toSeconds() + "s to wait)",
                    user.getUsername(),
                    ipAddress,
                    userAgent,
                    SecurityEventType.SIGN_IN_THROTTLED));
            throw new PasswordLockedException(attempt.retryAfter());
        }
        if (!PasswordHasher.verify(password, user.getPassword())) {
            // The reservation stays: it is this failure.
            audit.record(new AuditLogService.Record(
                    AuditOperation.LOGIN_FAILURE,
                    String.valueOf(user.getId()),
                    "MFA enrolment refused: the current password was wrong",
                    user.getUsername(),
                    ipAddress,
                    userAgent));
            throw new CurrentPasswordWrongException();
        }
        auth.clearPasswordFailures(user.getId(), ipAddress);
        // Enrolling over an active factor replaced it with no proof of the old one: a session
        // left open on somebody's desk was enough to move their second factor onto one's own
        // phone. Disabling asks for a code, so replacing goes through disabling.
        if (user.getMfaEnabled()) {
            throw new InvalidInputException(
                    "MFA is already enabled. Disable it with a current code before enrolling a new device.");
        }
        OptionalLong step = Totp.matchingStep(secret, code, clock.instant());
        if (step.isEmpty()) {
            throw new InvalidInputException("Invalid TOTP verification code.");
        }

        List<String> backupCodes = Totp.generateBackupCodes(8);
        String backupSerialized = String.join(",", backupCodes);

        String encryptedSecret = encryption.encrypt(secret, TOTP_CONTEXT + ":" + user.getId());
        String encryptedBackups = encryption.encrypt(backupSerialized, BACKUP_CONTEXT + ":" + user.getId());

        user.setMfaEnabled(true);
        user.setTotpSecret(encryptedSecret);
        user.setMfaBackupCodes(encryptedBackups);
        // The code that proved the enrolment was seen on this request; it opens no sign-in after.
        user.setTotpLastStep(step.getAsLong());
        user.setUpdatedAt(clock.instant());
        users.save(user);

        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                user.getId().toString(),
                "MFA / TOTP enabled for user: " + user.getUsername(),
                user.getUsername(),
                null,
                null));

        return new EnableResponse(true, backupCodes);
    }

    /** Reads the row by the account's id, as {@link #enable} does. */
    public void disable(UserView account, String code) {
        UserEntity user = users.findById(account.id()).orElseThrow();
        // **The same budget as the sign-in challenge.** Disabling asks for a code, and it had no
        // ceiling: a session left open on somebody's desk could try codes here without limit and,
        // at a million possibilities, eventually disarm the factor. Wrong codes count against the
        // account exactly as they do at sign-in, and a lockout there is a lockout here. Reserved
        // before the code is checked, so codes sent together cannot all read "under the ceiling".
        AuthService.Reservation attempt = auth.reserveSecondFactor(user.getId());
        if (!attempt.admitted()) {
            throw new SecondFactorLockedException(attempt.retryAfter());
        }
        if (!verify(user, code)) {
            // The reservation stays: it is this failure.
            throw new InvalidInputException("Invalid code or backup code. MFA could not be disabled.");
        }
        auth.clearSecondFactorFailures(user.getId());

        user.setMfaEnabled(false);
        user.setTotpSecret(null);
        user.setMfaBackupCodes(null);
        user.setTotpLastStep(null);
        user.setUpdatedAt(clock.instant());
        users.save(user);

        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                user.getId().toString(),
                "MFA / TOTP disabled for user: " + user.getUsername(),
                user.getUsername(),
                null,
                null));
    }

    /**
     * Re-seals the secret and the backup codes still under a previous key, each only if it is still
     * the value read: of two sign-ins at once one writes, and the other's value is the same secret
     * under the same current key. The entity follows what was written, so the checks below read the
     * new ciphertext — the backup codes' conditional replacement compares against it.
     */
    private void resealIfPrevious(UserEntity user) {
        String secretContext = TOTP_CONTEXT + ":" + user.getId();
        String secret = user.getTotpSecret();
        if (secret != null) {
            SecretCipher.Decrypted opened = encryption.inspect(secret, secretContext);
            if (opened.state() == SecretCipher.SecretState.PREVIOUS_KEY) {
                String resealed = encryption.encrypt(opened.plainText(), secretContext);
                if (users.replaceTotpSecret(user.getId(), secret, resealed) == 1) {
                    user.setTotpSecret(resealed);
                }
            }
        }
        String backupContext = BACKUP_CONTEXT + ":" + user.getId();
        String backups = user.getMfaBackupCodes();
        if (backups != null) {
            SecretCipher.Decrypted opened = encryption.inspect(backups, backupContext);
            if (opened.state() == SecretCipher.SecretState.PREVIOUS_KEY) {
                String resealed = encryption.encrypt(opened.plainText(), backupContext);
                if (users.replaceBackupCodes(user.getId(), backups, resealed, clock.instant()) == 1) {
                    user.setMfaBackupCodes(resealed);
                }
            }
        }
    }

    @Override
    public List<StoreCensus> census() {
        StoreCensus.Counter secrets = new StoreCensus.Counter("TOTP secrets",
                "re-sealed at the account's next second-factor check, or by enrolling again");
        StoreCensus.Counter backups = new StoreCensus.Counter("TOTP backup codes",
                "re-sealed at the account's next second-factor check, or by enrolling again");
        for (UserEntity user : users.findHoldingSecondFactorSecrets()) {
            secrets.add(encryption.sealOf(user.getTotpSecret(), TOTP_CONTEXT + ":" + user.getId()));
            backups.add(encryption.sealOf(user.getMfaBackupCodes(), BACKUP_CONTEXT + ":" + user.getId()));
        }
        return List.of(secrets.done(), backups.done());
    }

    public boolean verify(UserEntity user, String codeOrBackup) {
        if (user == null || !user.getMfaEnabled() || codeOrBackup == null || codeOrBackup.isBlank()) {
            return false;
        }

        String cleaned = codeOrBackup.trim();

        // **A value opened by a previous key is re-sealed under the current one as it is read.**
        // These are read at sign-in and nowhere else, and written only at enrolment: after a
        // rotation they stayed under the old key for good, and removing it — as the procedure said
        // once the SSH keys were done — refused the second factor of every enrolled account. Read
        // here, after the password has been proved or by a session, and before the code is
        // judged, so an account that only mistypes is moved too.
        resealIfPrevious(user);

        // 1. Try TOTP code
        if (cleaned.length() == 6 && user.getTotpSecret() != null) {
            SecretCipher.Decrypted decrypted = encryption.inspect(user.getTotpSecret(), TOTP_CONTEXT + ":" + user.getId());
            if (decrypted.state() != SecretCipher.SecretState.UNREADABLE) {
                OptionalLong step = Totp.matchingStep(decrypted.plainText(), cleaned, clock.instant());
                // A right code already used is refused like a wrong one: it is the replay.
                if (step.isPresent() && users.advanceTotpStep(user.getId(), step.getAsLong()) == 1) {
                    user.setTotpLastStep(step.getAsLong());
                    return true;
                }
            }
        }

        // 2. Try Emergency Backup Code
        String stored = user.getMfaBackupCodes();
        if (stored != null) {
            SecretCipher.Decrypted decrypted = encryption.inspect(stored, BACKUP_CONTEXT + ":" + user.getId());
            if (decrypted.state() != SecretCipher.SecretState.UNREADABLE) {
                List<String> codes = new ArrayList<>(Arrays.asList(decrypted.plainText().split(",")));
                if (codes.remove(cleaned)) {
                    String remaining = encryption.encrypt(String.join(",", codes), BACKUP_CONTEXT + ":" + user.getId());
                    // Spent only if the codes are still the ones read: otherwise another sign-in
                    // spent one in between — perhaps this one — and a second success would be
                    // the same code accepted twice.
                    if (users.replaceBackupCodes(user.getId(), stored, remaining, clock.instant()) != 1) {
                        return false;
                    }
                    user.setMfaBackupCodes(remaining);

                    audit.record(new AuditLogService.Record(
                            AuditOperation.USER_UPDATED,
                            user.getId().toString(),
                            "Emergency backup recovery code used by: " + user.getUsername(),
                            user.getUsername(),
                            null,
                            null,
                            SecurityEventType.MFA_BACKUP_CODE_USED));
                    return true;
                }
            }
        }

        return false;
    }
}

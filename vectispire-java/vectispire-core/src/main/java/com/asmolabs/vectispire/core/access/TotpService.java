package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
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
public class TotpService {

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

    public record SetupResponse(String secret, String qrCodeUri, String issuer) {}

    public record EnableResponse(boolean success, List<String> backupCodes) {}

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
     * @throws java.util.NoSuchElementException when the account is gone — only a deletion racing
     *     this request, which the bearer filter found active
     */
    public EnableResponse enable(UserView account, String secret, String code) {
        UserEntity user = users.findById(account.id()).orElseThrow();
        // Enrolling over an active factor replaced it with no proof of the old one: a session
        // left open on somebody's desk was enough to move their second factor onto one's own
        // phone. Disabling asks for a code, so replacing goes through disabling.
        if (user.getMfaEnabled()) {
            throw new IllegalArgumentException(
                    "MFA is already enabled. Disable it with a current code before enrolling a new device.");
        }
        OptionalLong step = Totp.matchingStep(secret, code, clock.instant());
        if (step.isEmpty()) {
            throw new IllegalArgumentException("Invalid TOTP verification code.");
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
        // account exactly as they do at sign-in, and a lockout there is a lockout here.
        java.time.Duration locked = auth.secondFactorLockout(user.getId());
        if (!locked.isZero()) {
            throw new SecondFactorLockedException(locked);
        }
        if (!verify(user, code)) {
            auth.recordSecondFactorFailure(user.getId());
            throw new IllegalArgumentException("Invalid code or backup code. MFA could not be disabled.");
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

    public boolean verify(UserEntity user, String codeOrBackup) {
        if (user == null || !user.getMfaEnabled() || codeOrBackup == null || codeOrBackup.isBlank()) {
            return false;
        }

        String cleaned = codeOrBackup.trim();

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

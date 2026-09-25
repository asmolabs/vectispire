package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
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

    private final Users users;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;

    public TotpService(Users users, EncryptionService encryption, AuditLogService audit, Clock clock) {
        this.users = users;
        this.encryption = encryption;
        this.audit = audit;
        this.clock = clock;
    }

    public record SetupResponse(String secret, String qrCodeUri, String issuer) {}

    public record EnableResponse(boolean success, List<String> backupCodes) {}

    public SetupResponse setup(UserEntity user) {
        String secret = Totp.generateSecret();
        String issuer = "Vectispire";
        String qrUri = Totp.qrCodeUri(user.getUsername(), secret, issuer);
        return new SetupResponse(secret, qrUri, issuer);
    }

    public EnableResponse enable(UserEntity user, String secret, String code) {
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

    public void disable(UserEntity user, String code) {
        if (!verify(user, code)) {
            throw new IllegalArgumentException("Invalid code or backup code. MFA could not be disabled.");
        }

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
                            null));
                    return true;
                }
            }
        }

        return false;
    }
}

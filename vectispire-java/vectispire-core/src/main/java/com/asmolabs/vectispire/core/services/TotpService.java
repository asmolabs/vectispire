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
        if (!Totp.verify(secret, code, clock.instant())) {
            throw new IllegalArgumentException("Invalid TOTP verification code.");
        }

        List<String> backupCodes = Totp.generateBackupCodes(8);
        String backupSerialized = String.join(",", backupCodes);

        String encryptedSecret = encryption.encrypt(secret, TOTP_CONTEXT + ":" + user.getId());
        String encryptedBackups = encryption.encrypt(backupSerialized, BACKUP_CONTEXT + ":" + user.getId());

        user.setMfaEnabled(true);
        user.setTotpSecret(encryptedSecret);
        user.setMfaBackupCodes(encryptedBackups);
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
                if (Totp.verify(decrypted.plainText(), cleaned, clock.instant())) {
                    return true;
                }
            }
        }

        // 2. Try Emergency Backup Code
        if (user.getMfaBackupCodes() != null) {
            SecretCipher.Decrypted decrypted = encryption.inspect(user.getMfaBackupCodes(), BACKUP_CONTEXT + ":" + user.getId());
            if (decrypted.state() != SecretCipher.SecretState.UNREADABLE) {
                List<String> codes = new ArrayList<>(Arrays.asList(decrypted.plainText().split(",")));
                if (codes.remove(cleaned)) {
                    // Consume used backup code and re-encrypt remaining codes
                    String updatedSerialized = String.join(",", codes);
                    user.setMfaBackupCodes(encryption.encrypt(updatedSerialized, BACKUP_CONTEXT + ":" + user.getId()));
                    user.setUpdatedAt(clock.instant());
                    users.save(user);

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

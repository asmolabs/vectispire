package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.core.persistence.UserEntity;
import java.time.Instant;

/**
 * An account as the layers above the services hold it: the row's properties, not the row.
 *
 * <p><b>Why not the entity.</b> The principal carried the {@code UserEntity} the bearer filter
 * loaded, so every controller could reach its password hash, its TOTP secret and its backup codes,
 * and hand the row back to a service that saved whatever had been done to it on the way. Nothing
 * of the persistence layer reaches {@code api} any more ({@code ArchitectureTest}); a service that
 * needs a secret reads the row itself, by {@link #id}, inside its own transaction.
 *
 * <p>The secrets are left out on purpose, not forgotten: {@code password}, {@code totpSecret},
 * {@code mfaBackupCodes} and {@code totpLastStep}. Every other property keeps the entity's name.
 */
public record UserView(
        Long id,
        String username,
        String email,
        String displayName,
        String avatarUrl,
        String role,
        boolean isActive,
        String githubId,
        String keycloakId,
        Instant createdAt,
        Instant updatedAt,
        boolean mustChangePassword,
        boolean mfaEnabled) {

    public static UserView of(UserEntity user) {
        return new UserView(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getDisplayName(),
                user.getAvatarUrl(),
                user.getRole(),
                user.getIsActive(),
                user.getGithubId(),
                user.getKeycloakId(),
                user.getCreatedAt(),
                user.getUpdatedAt(),
                user.getMustChangePassword(),
                user.getMfaEnabled());
    }
}

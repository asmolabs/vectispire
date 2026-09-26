package com.asmolabs.vectispire.core.siem;

import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import java.time.Instant;

/**
 * The SIEM export's configuration as the layers above the services hold it: the row's properties
 * under their own names, not the row.
 *
 * <p><b>The authorization header is not here, only whether one is set.</b> The column holds its
 * ciphertext, which the screen never showed and no route has a use for; {@link #hasAuthHeader}
 * is the one fact the screen displays about it.
 */
public record SiemConfigView(
        Long id,
        boolean enabled,
        String protocol,
        String endpoint,
        boolean hasAuthHeader,
        String minSeverity,
        Instant createdAt,
        Instant updatedAt) {

    public static SiemConfigView of(SiemConfigEntity row) {
        return new SiemConfigView(
                row.getId(),
                row.isEnabled(),
                row.getProtocol(),
                row.getEndpoint(),
                row.getAuthHeader() != null && !row.getAuthHeader().isBlank(),
                row.getMinSeverity(),
                row.getCreatedAt(),
                row.getUpdatedAt());
    }
}

package com.asmolabs.vectispire.core.siem;

import com.asmolabs.vectispire.common.domain.siem.CollectorCa;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import java.time.Instant;
import java.util.Optional;

/**
 * The SIEM export's configuration as the layers above the services hold it: the row's properties
 * under their own names, not the row.
 *
 * <p><b>The authorization header is not here, only whether one is set.</b> The column holds its
 * ciphertext, which the screen never showed and no route has a use for; {@link #hasAuthHeader}
 * is the one fact the screen displays about it.
 *
 * <p><b>The pinned CA is here in full</b>, being public, so the form can show and resubmit it; its
 * subject and earliest expiry are read from it so the screen can say which CA is pinned and when it
 * stops working — {@code null} for both when none is pinned, or when the stored text no longer reads
 * as one (a row edited by hand: the delivery refuses it, and the screen shows the PEM to replace).
 */
public record SiemConfigView(
        Long id,
        boolean enabled,
        String protocol,
        String endpoint,
        boolean hasAuthHeader,
        String minSeverity,
        String tlsCaPem,
        String tlsCaSubject,
        Instant tlsCaNotAfter,
        Instant createdAt,
        Instant updatedAt) {

    public static SiemConfigView of(SiemConfigEntity row) {
        Optional<CollectorCa> ca = describe(row.getTlsCaPem());
        return new SiemConfigView(
                row.getId(),
                row.isEnabled(),
                row.getProtocol(),
                row.getEndpoint(),
                row.getAuthHeader() != null && !row.getAuthHeader().isBlank(),
                row.getMinSeverity(),
                row.getTlsCaPem(),
                ca.map(CollectorCa::subject).orElse(null),
                ca.map(CollectorCa::notAfter).orElse(null),
                row.getCreatedAt(),
                row.getUpdatedAt());
    }

    private static Optional<CollectorCa> describe(String pem) {
        if (pem == null || pem.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(CollectorCa.read(pem));
        } catch (IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }
}

package com.asmolabs.vectispire.common.domain.siem;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * How the SIEM configuration says events travel.
 *
 * <p>The four values the settings screen offers and the published contract declares. The column
 * was a free {@code varchar(16)}, so anything was stored — a typo, or a string that overflowed it
 * and came back as a 500 — and nothing could tell a configured protocol from garbage.
 *
 * <p><b>What is stored is not yet what is spoken.</b> The exporter sends every event as an HTTP
 * POST, whatever this says; the three syslog values are accepted because the screen offers them,
 * and honouring them is a feature of its own, not something validation can supply.
 */
public enum SiemProtocol {
    WEBHOOK,
    SYSLOG_UDP,
    SYSLOG_TCP,
    SYSLOG_TLS;

    /** The protocol a submitted value names, case aside, or empty when it names none. */
    public static Optional<SiemProtocol> byName(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(values()).filter(protocol -> protocol.name().equals(normalized)).findFirst();
    }
}

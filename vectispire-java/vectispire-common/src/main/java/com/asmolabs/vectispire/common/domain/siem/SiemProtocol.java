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
 * <p><b>What is stored is what is spoken.</b> It was not: every event went out as an HTTP POST
 * whatever this said, and the three syslog values were accepted only because the screen offered
 * them. Each value now names a transport — see {@link SiemEndpoint} for the endpoint each reads,
 * and {@link SyslogMessage} for the framing of the three syslog ones.
 */
public enum SiemProtocol {
    WEBHOOK,
    SYSLOG_UDP,
    SYSLOG_TCP,
    SYSLOG_TLS;

    /**
     * Whether a configured header travels with each event. Only an HTTP request has headers; a
     * syslog frame has nowhere to put one, and pretending otherwise would let a screen collect a
     * credential that is never used.
     */
    public boolean carriesHeaders() {
        return this == WEBHOOK;
    }

    /** The protocol a submitted value names, case aside, or empty when it names none. */
    public static Optional<SiemProtocol> byName(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(values()).filter(protocol -> protocol.name().equals(normalized)).findFirst();
    }
}

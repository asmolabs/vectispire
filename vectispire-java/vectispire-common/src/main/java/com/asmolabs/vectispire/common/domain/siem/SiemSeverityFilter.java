package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Which events the configured minimum severity lets through.
 *
 * <p>The setting speaks the product's four severities — {@code CRITICAL}, {@code HIGH},
 * {@code MEDIUM}, {@code LOW} — and an event carries a CEF severity from 0 to 10. The bridge is the
 * CEF convention every SIEM already applies to render its own colours: 9–10 very high, 7–8 high,
 * 4–6 medium, 0–3 low. So {@code HIGH} forwards 7 and above, and a SOC reading the severity column
 * sees the same band the filter used.
 *
 * <p>The value was stored and never read: every event went out whatever the screen said.
 */
public final class SiemSeverityFilter {

    private SiemSeverityFilter() {}

    /**
     * Whether an event of this type is forwarded under this stored minimum.
     *
     * <p><b>Null or blank sends everything</b>: no threshold is not a threshold of "nothing". And
     * <b>an unreadable value sends everything too</b> — a row edited by hand, or a severity a later
     * version adds. For a security feed the failure worth having is noise in a SOC, not silence
     * nobody sees; the save path refuses anything but the four values, so this only ever meets a
     * value that did not come through it.
     *
     * <p>{@link SecurityEventType#PING_TEST} always passes: it tests the destination, and a filter
     * that swallowed it would make the connection test report a failure on a working collector.
     */
    public static boolean admits(SecurityEventType type, String storedMinimum) {
        if (type == SecurityEventType.PING_TEST) {
            return true;
        }
        return minimumOf(storedMinimum).map(floor -> type.cefSeverity() >= floor).orElse(true);
    }

    /** The lowest CEF severity a stored minimum forwards, or empty when it forwards everything. */
    static Optional<Integer> minimumOf(String storedMinimum) {
        if (storedMinimum == null || storedMinimum.isBlank()) {
            return Optional.empty();
        }
        String normalized = storedMinimum.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(Severity.values())
                .filter(severity -> severity.name().equals(normalized))
                .findFirst()
                .flatMap(SiemSeverityFilter::cefFloor);
    }

    /**
     * The CEF band's lower edge.
     *
     * <p>A switch without a default so a severity added to {@link Severity} has to be placed here.
     * {@code NEGLIGIBLE} and {@code UNKNOWN} are not offered by the screen; both mean "the lowest",
     * which forwards everything.
     */
    private static Optional<Integer> cefFloor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> Optional.of(9);
            case HIGH -> Optional.of(7);
            case MEDIUM -> Optional.of(4);
            case LOW, NEGLIGIBLE, UNKNOWN -> Optional.empty();
        };
    }
}

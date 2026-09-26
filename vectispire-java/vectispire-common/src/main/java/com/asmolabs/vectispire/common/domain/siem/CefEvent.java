package com.asmolabs.vectispire.common.domain.siem;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * An immutable ArcSight Common Event Format (CEF) event.
 *
 * <p>{@code CEF:0|Vectispire|ASPM|<version>|<signature id>|<name>|<severity>|<extension>}
 *
 * <h2>Escaping is a security control here, not formatting</h2>
 *
 * <p>Several extension values come from whoever is on the other side of a form: the username a
 * sign-in attempt typed, a resource identifier, an audit description. A username of
 * {@code x\nCEF:0|Vectispire|ASPM|1|ZAN-SEC-018|…} written raw would be a second event in every
 * line-oriented collector — a forged alarm, or a forged all-clear. So:
 *
 * <ul>
 *   <li>in the header, {@code \} and {@code |} are escaped, as the specification requires;
 *   <li>in extension values, {@code \} and {@code =} are escaped, and CR and LF become {@code \r}
 *       and {@code \n}, as the specification requires. A pipe needs no escape there — parsers split
 *       the header on the first seven — and escaping one would print a stray backslash;
 *   <li>every other control character, in the header or in a value, becomes a space. The
 *       specification says nothing about them, and a NUL or an escape sequence reaching a
 *       terminal or a C parser is not worth preserving.
 * </ul>
 *
 * <p>Extension keys are ours, never a caller's: they are checked to be alphanumeric and a bad one
 * is a programming error, thrown rather than escaped, because an escaped key is still a key no
 * SIEM will recognise.
 */
public record CefEvent(
        SecurityEventType eventType,
        Instant timestamp,
        String message,
        Map<String, String> extensions) {

    private static final Pattern EXTENSION_KEY = Pattern.compile("[A-Za-z0-9]+");

    public CefEvent {
        if (eventType == null) throw new IllegalArgumentException("eventType is required");
        if (timestamp == null) timestamp = Instant.now();
        extensions = extensions != null ? Collections.unmodifiableMap(new LinkedHashMap<>(extensions)) : Map.of();
        extensions.keySet().forEach(CefEvent::requireKey);
    }

    public static Builder builder(SecurityEventType eventType) {
        return new Builder(eventType);
    }

    /**
     * The event as one CEF line.
     *
     * @param deviceVersion the product's version, or {@code null} when nothing states one — the
     *     field is then left empty rather than filled with a number nobody shipped
     */
    public String toCefString(String deviceVersion) {
        String header = "CEF:0|Vectispire|ASPM|"
                + escapeHeader(deviceVersion) + "|"
                + escapeHeader(eventType.signatureId()) + "|"
                + escapeHeader(eventType.description()) + "|"
                + eventType.cefSeverity() + "|";

        Map<String, String> ext = new LinkedHashMap<>();
        ext.put("rt", String.valueOf(timestamp.toEpochMilli()));
        ext.put("outcome", eventType.outcome().wireName());
        ext.putAll(extensions);
        if (message != null && !message.isBlank()) {
            ext.put("msg", message);
        }

        return header + ext.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + escapeExtensionValue(entry.getValue()))
                .collect(Collectors.joining(" "));
    }

    static String escapeHeader(String value) {
        if (value == null) return "";
        return neutralizeControls(value.replace("\\", "\\\\").replace("|", "\\|"));
    }

    static String escapeExtensionValue(String value) {
        if (value == null) return "";
        String escaped = value.replace("\\", "\\\\")
                .replace("=", "\\=")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
        return neutralizeControls(escaped);
    }

    /**
     * Every remaining control character as a space: C0, DEL, C1 and the Unicode line and paragraph
     * separators, which some collectors split on. In the header that includes CR and LF, which it
     * has no escape for; in a value they were already turned into their escapes.
     */
    private static String neutralizeControls(String value) {
        StringBuilder out = new StringBuilder(value.length());
        value.codePoints().forEach(c -> {
            boolean control = c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0)
                    || c == 0x2028 || c == 0x2029;
            out.appendCodePoint(control ? ' ' : c);
        });
        return out.toString();
    }

    private static void requireKey(String key) {
        if (key == null || !EXTENSION_KEY.matcher(key).matches()) {
            throw new IllegalArgumentException("Not a CEF extension key: " + key);
        }
    }

    public static class Builder {
        private final SecurityEventType eventType;
        private Instant timestamp = Instant.now();
        private String message;
        private final Map<String, String> extensions = new LinkedHashMap<>();

        public Builder(SecurityEventType eventType) {
            this.eventType = eventType;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        /** {@code suser}: the account that acted, as the audit entry names it. */
        public Builder user(String username) {
            return put("suser", username);
        }

        /** {@code src}: the client address, already resolved against the trusted proxies. */
        public Builder sourceIp(String ip) {
            return put("src", ip);
        }

        /** {@code act}: what was done, as the audit log names the operation. */
        public Builder action(String action) {
            return put("act", action);
        }

        /** {@code externalId}: the outbox message identifier, which is what a receiver deduplicates on. */
        public Builder externalId(String id) {
            return put("externalId", id);
        }

        /** {@code cs1}: the resource acted upon — an issue, an account, a key, a setting. */
        public Builder target(String target) {
            return labelled(1, "Target", target);
        }

        /** {@code cs2}: the user agent the request carried. */
        public Builder userAgent(String userAgent) {
            return labelled(2, "UserAgent", userAgent);
        }

        /** {@code cs3}: a CVE, a rule or a secret identifier. */
        public Builder identifier(String identifier) {
            return labelled(3, "Identifier", identifier);
        }

        /** {@code cs4}: the package or component concerned. */
        public Builder component(String component) {
            return labelled(4, "Component", component);
        }

        public Builder extension(String key, String value) {
            if (key != null && value != null) {
                extensions.put(key, value);
            }
            return this;
        }

        public CefEvent build() {
            return new CefEvent(eventType, timestamp, message, extensions);
        }

        private Builder labelled(int slot, String label, String value) {
            if (value != null && !value.isBlank()) {
                extensions.put("cs" + slot + "Label", label);
                extensions.put("cs" + slot, value);
            }
            return this;
        }

        private Builder put(String key, String value) {
            if (value != null && !value.isBlank()) {
                extensions.put(key, value);
            }
            return this;
        }
    }
}

package com.asmolabs.vectispire.common.domain.siem;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * An immutable ArcSight Common Event Format (CEF v0.1) event.
 *
 * <p>Format specification:
 * {@code CEF:0|Vectispire|ASPM|1.0|signatureId|name|severity|extension}
 */
public record CefEvent(
        SecurityEventType eventType,
        Instant timestamp,
        String message,
        Map<String, String> extensions) {

    public CefEvent {
        if (eventType == null) throw new IllegalArgumentException("eventType is required");
        if (timestamp == null) timestamp = Instant.now();
        extensions = extensions != null ? Collections.unmodifiableMap(new LinkedHashMap<>(extensions)) : Map.of();
    }

    public static Builder builder(SecurityEventType eventType) {
        return new Builder(eventType);
    }

    public String toCefString() {
        String header = String.format(
                "CEF:0|Vectispire|ASPM|1.0|%s|%s|%d|",
                escapeHeader(eventType.signatureId()),
                escapeHeader(eventType.description()),
                eventType.cefSeverity());

        Map<String, String> ext = new LinkedHashMap<>(extensions);
        ext.put("rt", String.valueOf(timestamp.toEpochMilli()));
        if (message != null && !message.isBlank()) {
            ext.put("msg", message);
        }

        String extensionString = ext.entrySet().stream()
                .map(e -> escapeExtensionKey(e.getKey()) + "=" + escapeExtensionValue(e.getValue()))
                .collect(Collectors.joining(" "));

        return header + extensionString;
    }

    private static String escapeHeader(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("|", "\\|");
    }

    private static String escapeExtensionKey(String key) {
        if (key == null) return "";
        return key.replace("\\", "\\\\").replace("=", "\\=");
    }

    private static String escapeExtensionValue(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r");
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

        public Builder user(String username) {
            if (username != null && !username.isBlank()) {
                extensions.put("suser", username);
            }
            return this;
        }

        public Builder sourceIp(String ip) {
            if (ip != null && !ip.isBlank()) {
                extensions.put("src", ip);
            }
            return this;
        }

        public Builder target(String target) {
            if (target != null && !target.isBlank()) {
                extensions.put("cs1Label", "Target");
                extensions.put("cs1", target);
            }
            return this;
        }

        public Builder assetTier(String tier) {
            if (tier != null && !tier.isBlank()) {
                extensions.put("cs2Label", "AssetTier");
                extensions.put("cs2", tier);
            }
            return this;
        }

        public Builder identifier(String cveOrSecret) {
            if (cveOrSecret != null && !cveOrSecret.isBlank()) {
                extensions.put("cs3Label", "Identifier");
                extensions.put("cs3", cveOrSecret);
            }
            return this;
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
    }
}

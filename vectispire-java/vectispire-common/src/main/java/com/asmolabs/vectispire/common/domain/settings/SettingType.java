package com.asmolabs.vectispire.common.domain.settings;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.List;
import java.util.Optional;

/**
 * What a setting's value has to look like, and the rejection message when it does not.
 *
 * <p><b>Validated at the point of entry, never on read.</b> An unreadable integer read later
 * falls back to its default, and the operator never learns their value was ignored — they
 * configured something, the behaviour did not change, and they conclude the tool is broken.
 */
public enum SettingType {
    BOOLEAN {
        @Override
        public Optional<String> validate(String value) {
            return "true".equals(value) || "false".equals(value)
                    ? Optional.empty()
                    : Optional.of("Expected value: \"true\" or \"false\".");
        }
    },

    INTEGER {
        @Override
        public Optional<String> validate(String value) {
            if (value == null || value.isBlank()) {
                return Optional.of(MESSAGE);
            }
            try {
                return Integer.parseInt(value.trim()) >= 0 ? Optional.empty() : Optional.of(MESSAGE);
            } catch (NumberFormatException notANumber) {
                return Optional.of(MESSAGE);
            }
        }

        private static final String MESSAGE = "Expected value: a positive integer or zero.";
    },

    SEVERITY {
        /**
         * Deliberately narrower than {@link Severity}.
         *
         * <p>{@code negligible} and {@code unknown} are absent because this type is only used
         * for <em>thresholds</em>, and a threshold of "unknown" notifies on everything —
         * including every advisory the OSV backend returns without a normalized severity. That
         * is not a setting anybody wants, and offering it in a dropdown is offering a way to
         * flood the channel by accident.
         */
        @Override
        public Optional<String> validate(String value) {
            return THRESHOLDS.stream().anyMatch(severity -> severity.wireName().equals(value))
                    ? Optional.empty()
                    : Optional.of("Expected value: critical, high, medium or low.");
        }
    },

    TEXT {
        @Override
        public Optional<String> validate(String value) {
            // Free text. What the value has to *mean* — a URL that resolves somewhere allowed,
            // a provider from a known list — is checked by whoever reads it, because only they
            // know the rule.
            return Optional.empty();
        }
    };

    /** The severities usable as a threshold. */
    public static final List<Severity> THRESHOLDS =
            List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW);

    /** Empty when the value is acceptable, otherwise the message to show. */
    public abstract Optional<String> validate(String value);
}

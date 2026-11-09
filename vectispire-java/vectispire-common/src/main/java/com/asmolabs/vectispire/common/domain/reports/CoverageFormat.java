package com.asmolabs.vectispire.common.domain.reports;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * The coverage formats an import reads, <b>declared by the pipeline and never sniffed</b>.
 *
 * <p>A body that does not read as its declared format is refused, rather than tried as the others:
 * a reader that guesses would one day read a truncated JaCoCo file as a valid lcov one, and record
 * whatever figure the accident produced.
 */
public enum CoverageFormat {
    JACOCO,
    COBERTURA,
    LCOV;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** The declared format, or a refusal naming the ones accepted. */
    public static CoverageFormat parse(String value) {
        String normalized = value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(format -> format.wireName().equals(normalized))
                .findFirst()
                .orElseThrow(() -> new InvalidInputException("Declare the report's format as one of "
                        + Arrays.stream(values()).map(CoverageFormat::wireName).collect(Collectors.joining(", "))
                        + (normalized.isEmpty() ? "" : "; \"" + BoundedText.clip(value.strip(), 40) + "\" is not one of them") + "."));
    }
}

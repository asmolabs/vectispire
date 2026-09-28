package com.asmolabs.vectispire.common.domain.aireview;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * The language a model is asked to explain a vulnerability in: the one the reader's screen is shown in.
 *
 * <p>The prompt asked for French whoever asked. No account and no instance setting records a
 * language — the interface keeps the reader's choice in the browser — so the screen says which one
 * it shows, and a caller that says nothing gets English. The two the interface is translated into,
 * and no more: a model asked for a language nobody reads here would answer in it.
 */
public enum AdviceLanguage {
    ENGLISH("en", "English"),
    FRENCH("fr", "French");

    private final String code;
    private final String englishName;

    AdviceLanguage(String code, String englishName) {
        this.code = code;
        this.englishName = englishName;
    }

    /** The language's name as the prompt spells it — the prompt itself is English. */
    public String englishName() {
        return englishName;
    }

    /**
     * The language a request names, by its code ({@code en}, {@code fr}).
     *
     * @return English when none is given
     * @throws InvalidInputException for a code that is not one of these, naming those that are
     */
    public static AdviceLanguage parse(String code) {
        if (code == null || code.isBlank()) {
            return ENGLISH;
        }
        String asked = code.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(language -> language.code.equals(asked))
                .findFirst()
                .orElseThrow(() -> new InvalidInputException("language must be one of "
                        + Arrays.stream(values()).map(language -> language.code).collect(Collectors.joining(", "))
                        + "."));
    }
}

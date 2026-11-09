package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The languages a scan's census found in its tree, as the scan keeps them in {@code
 * detected_languages}.
 *
 * <p><b>One vocabulary: {@link Language}'s wire names</b> — what a plugin manifest declares, and the
 * Semgrep catalogue's directories a rule set covers. A screen puts a plugin's {@code languages} beside
 * a repository's {@code detectedLanguages} and compares the strings as they are; a second spelling
 * ("TypeScript", "ts") would be a mapping somebody has to keep in step, and the day it drifts a
 * plugin reads as not applying to a project it applies to.
 *
 * <p><b>Three answers, not two</b>, as for {@link ExaminedTypes}: a set is "the census walked the whole
 * tree and these languages are in it"; the empty set is "it walked the whole tree and no file named a
 * language"; {@link Optional#empty()} is "nobody knows" — a scan from before V57, an image, a census
 * that stopped at its bounds, an agent older than the field. Reading the last as the second would tell
 * an operator a Java repository holds no Java (decision 0007).
 */
public final class DetectedLanguages {

    private DetectedLanguages() {}

    /**
     * The column: wire names, sorted, comma-separated; the empty string for the empty set; null when
     * nothing was recorded. A name this version does not know — sent by a newer executor — is left out:
     * what the column claims, this version can read back.
     */
    static String write(Optional<? extends Collection<String>> names) {
        return names.map(present -> present.stream()
                        .map(Language::fromWireName)
                        .flatMap(Optional::stream)
                        .map(Language::wireName)
                        .distinct()
                        .sorted()
                        .collect(Collectors.joining(",")))
                .orElse(null);
    }

    /**
     * The column read back. A name this version does not know — written by a later one, before a
     * rollback — is left out rather than failing the page; what it does know stays true.
     */
    public static Optional<Set<Language>> read(String column) {
        if (column == null) {
            return Optional.empty();
        }
        Set<Language> languages = EnumSet.noneOf(Language.class);
        Arrays.stream(column.split(","))
                .map(String::trim)
                .filter(name -> !name.isEmpty())
                .forEach(name -> Language.fromWireName(name).ifPresent(languages::add));
        return Optional.of(Collections.unmodifiableSet(languages));
    }
}

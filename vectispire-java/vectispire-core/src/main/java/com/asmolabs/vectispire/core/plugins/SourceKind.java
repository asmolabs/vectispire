package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * What a declared source may deliver (decision 0032 §7) — and which key scope delivering it takes.
 *
 * <p>One pipeline, one key, one declaration: a source that sends SARIF and coverage is one source
 * with two kinds, not two sources. The scope stays per kind of document — {@code sarif_import} for
 * SARIF, which opens and resolves issues, {@code report_import} for the two reports, which only
 * record a figure — so a key issued for coverage never deposits findings.
 */
public enum SourceKind {
    SARIF(ApiKeyScope.SARIF_IMPORT),
    COVERAGE(ApiKeyScope.REPORT_IMPORT),
    TEST_REPORT(ApiKeyScope.REPORT_IMPORT);

    private final ApiKeyScope scope;

    SourceKind(ApiKeyScope scope) {
        this.scope = scope;
    }

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** The scope a key must hold for a source to be declared with this kind. */
    public ApiKeyScope scope() {
        return scope;
    }

    /**
     * The kinds as a declaration states them. Absent is SARIF alone — what every source was before
     * kinds existed, so a client that never heard of them declares what it always declared; an empty
     * list is a source that may deliver nothing, and is refused.
     */
    public static Set<SourceKind> parseAll(List<String> names) {
        if (names == null) {
            return EnumSet.of(SARIF);
        }
        if (names.isEmpty()) {
            throw new InvalidInputException("A source delivers at least one kind of report.");
        }
        Set<SourceKind> kinds = EnumSet.noneOf(SourceKind.class);
        for (String value : names) {
            String normalized = value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
            kinds.add(Arrays.stream(values())
                    .filter(kind -> kind.wireName().equals(normalized))
                    .findFirst()
                    .orElseThrow(() -> new InvalidInputException("A source delivers "
                            + Arrays.stream(values()).map(SourceKind::wireName).collect(Collectors.joining(", "))
                            + "; \"" + BoundedText.clip(normalized, 40) + "\" is none of them.")));
        }
        return kinds;
    }

    /** As stored: comma-separated wire names, in declaration order, so equal sets store equal strings. */
    static String stored(Set<SourceKind> kinds) {
        return kinds.stream().sorted().map(SourceKind::wireName).collect(Collectors.joining(","));
    }

    /**
     * As read back. A name this version does not know is left out rather than refused: it grants
     * nothing here, and a row written by a later version must not stop this one reading the others.
     */
    static List<SourceKind> fromStored(String stored) {
        List<SourceKind> kinds = new ArrayList<>();
        if (stored == null) {
            return kinds;
        }
        for (String name : stored.split(",")) {
            Arrays.stream(values()).filter(kind -> kind.wireName().equals(name.strip())).findFirst().ifPresent(kinds::add);
        }
        return kinds;
    }
}

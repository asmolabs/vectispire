package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Which built-in steps looked at the tree, as the scan keeps it in {@code examined_types} (decision
 * 0032, §6).
 *
 * <p><b>Three answers, not two.</b> A set of types is "these steps produced"; the empty set is
 * "recorded, and no step produced"; {@link Optional#empty()} is "nobody recorded it" — a scan from
 * before V49, or one that never ran. Reading the last as the second would tell a checklist that a
 * repository scanned yesterday was never searched for secrets, when the truth is that nothing wrote
 * down whether it was; reading it as a full set would be worse, the vacuous pass decision 0007
 * forbids.
 *
 * <p>The set is the one the backlog resolves against, taken from {@link ScanIngestor} as it is handed
 * over — never inferred from the findings present, which would count a step that found nothing as a
 * step that did not run, and the other way round.
 *
 * <p><b>Built-in types only.</b> The tool-scoped ones ({@code plugin}, {@code imported}) are never in
 * it: a plugin's three states are in {@code plugin_steps}, and an import is its own row. The AI review
 * is no step of a scan.
 */
public final class ExaminedTypes {

    /** The types a scan's own steps can examine — what {@link ScanIngestor} may add to its set. */
    public static final Set<FindingType> BUILT_IN = Collections.unmodifiableSet(EnumSet.of(
            FindingType.VULNERABILITY,
            FindingType.SECRET,
            FindingType.IAC,
            FindingType.SAST,
            FindingType.QUALITY,
            FindingType.EOL,
            FindingType.LICENSE));

    private ExaminedTypes() {}

    /** The column: wire names, sorted, comma-separated; the empty string for the empty set. */
    static String write(Set<FindingType> examined) {
        return examined.stream().map(FindingType::wireName).sorted().collect(Collectors.joining(","));
    }

    /**
     * The column read back. A name this version does not know — written by a later one, before a
     * rollback — is left out rather than failing the scan's page; what it does know stays true.
     */
    static Optional<Set<FindingType>> read(String column) {
        if (column == null) {
            return Optional.empty();
        }
        Set<FindingType> types = EnumSet.noneOf(FindingType.class);
        Arrays.stream(column.split(","))
                .map(String::trim)
                .filter(name -> !name.isEmpty())
                .forEach(name -> FindingType.fromWireName(name).ifPresent(types::add));
        return Optional.of(Collections.unmodifiableSet(types));
    }

    /**
     * What a query matches the column against for one type: the list wrapped in commas on both sides,
     * so {@code sast} matches {@code ,iac,sast,} and never a longer name containing it. No built-in
     * wire name holds {@code %} or {@code _}, so nothing needs escaping — {@link #BUILT_IN} is what
     * guarantees it, and the callers refuse any other type.
     */
    static String pattern(FindingType type) {
        return "%," + type.wireName() + ",%";
    }
}

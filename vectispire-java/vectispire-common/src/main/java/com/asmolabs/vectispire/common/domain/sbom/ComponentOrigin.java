package com.asmolabs.vectispire.common.domain.sbom;

import java.util.Arrays;
import java.util.Locale;

/**
 * Who listed a component of a scan's inventory: the scanner, the build's SBOM, or both.
 *
 * <p>Provenance is shown, never inferred. A version the scanner wrote {@code UNKNOWN} and the build
 * stated reads as {@link #BOTH}, the build's version in front and the scanner's kept beside it; a
 * library only the build resolved reads as {@link #BUILD}, so a reviewer can tell it from one the
 * scanner found in the tree.
 */
public enum ComponentOrigin {
    SCANNER,
    BUILD,
    BOTH;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * As stored. Null is the scanner's: every row written before build SBOMs existed, and every row a
     * scan writes, which is the scanner's until a build SBOM completes it. A name this version does not
     * know reads as the scanner's too — the row is in the scan's inventory either way.
     */
    public static ComponentOrigin ofStored(String stored) {
        if (stored == null) {
            return SCANNER;
        }
        return Arrays.stream(values()).filter(origin -> origin.wireName().equals(stored)).findFirst().orElse(SCANNER);
    }

    /** As stored: the scanner's rows keep their null, so a scan's own write is untouched. */
    public String stored() {
        return this == SCANNER ? null : wireName();
    }

    /** Whether the build's SBOM lists the component. */
    public boolean fromBuild() {
        return this != SCANNER;
    }
}

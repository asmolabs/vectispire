package com.asmolabs.vectispire.common.domain.dependencies;

/**
 * Whether the project asked for a dependency, or something else dragged it in.
 *
 * <p>Three states, and {@link #UNKNOWN} is the one that matters. A nullable boolean spells the
 * same three, but nothing stops a caller reading absence as {@code false} — which turns "we do
 * not know" into "transitive", on the very field meant to decide what to fix first.
 */
public enum Directness {

    /** Declared in the project's own manifest: fixable this afternoon by changing one line. */
    DIRECT,

    /**
     * Pulled in by something else.
     *
     * <p>Waits on an upstream release, and may need a pin, a fork, or the decision to accept
     * the risk.
     */
    TRANSITIVE,

    /** The SBOM did not say. Not a synonym for {@link #TRANSITIVE}. */
    UNKNOWN;

    public static Directness of(boolean direct) {
        return direct ? DIRECT : TRANSITIVE;
    }

    /** The label used in exports and tickets, or empty when nothing is known. */
    public String label() {
        return switch (this) {
            case DIRECT -> "direct";
            case TRANSITIVE -> "transitive";
            // Empty rather than "unknown": a column filled with the word reads as a finding
            // about the dependency, when the honest statement is that we have nothing to say.
            case UNKNOWN -> "";
        };
    }
}

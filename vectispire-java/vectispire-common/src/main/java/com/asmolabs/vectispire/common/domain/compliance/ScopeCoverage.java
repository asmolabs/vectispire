package com.asmolabs.vectispire.common.domain.compliance;

/**
 * How much of the certified scope this instance can actually see.
 *
 * <h2>The number that matters is the one about what is missing</h2>
 *
 * <p><b>A tool measuring its own coverage always reports full coverage.</b> Vectispire knows the
 * targets somebody registered in it; a management system has a scope declared in a document, and
 * the two are not the same set. An estate where every target is scanned, made of half the
 * certified assets, is a finding dressed as a clean result — and nothing inside the database can
 * notice, because the missing assets have no row to be missing from.
 *
 * <p>So the scope statement's own asset count is carried alongside, entered by an operator from
 * the document that defines the scope. {@link #unaccountedFor()} is the subtraction, and it is the
 * figure an assessment opens with: <em>your scope names forty assets, this instance holds
 * thirty-one of them</em>. Everything else here describes the thirty-one.
 *
 * @param declaredAssets what the scope statement says it covers; zero means nobody has said
 * @param inScope targets marked as belonging to the certified scope
 * @param scannedRecently of those, the ones scanned inside the freshness window
 * @param stale in scope, scanned once, and not lately
 * @param neverScanned in scope and never scanned at all. <b>Worse than stale, and often hidden
 *     inside it</b>: a target scanned a year ago at least produced evidence once
 */
public record ScopeCoverage(
        int declaredAssets, int inScope, int scannedRecently, int stale, int neverScanned) {

    /**
     * Assets the scope statement claims that this instance holds no row for.
     *
     * <p>Zero when nobody has declared a count — <em>not</em> when the coverage is complete. The
     * two are told apart by {@link #declared()}, and confusing them is the whole trap: an
     * undeclared scope reports no gap for the same reason an empty room reports no noise.
     */
    public int unaccountedFor() {
        return declaredAssets <= 0 ? 0 : Math.max(0, declaredAssets - inScope);
    }

    /** Whether anybody has said what the scope covers. */
    public boolean declared() {
        return declaredAssets > 0;
    }

    /**
     * The share of the <em>declared</em> scope with fresh evidence, as a percentage.
     *
     * <p>Against the declared count and not against {@code inScope}, which is the point of the
     * record: dividing by what the instance happens to hold is how a tool reports a hundred per
     * cent on a third of an estate. Empty when nobody has declared a count — a percentage computed
     * against an unknown denominator is a number that will be quoted and should not exist.
     */
    public java.util.OptionalInt freshShareOfScope() {
        return declared()
                ? java.util.OptionalInt.of((int) Math.round(100.0 * scannedRecently / declaredAssets))
                : java.util.OptionalInt.empty();
    }
}

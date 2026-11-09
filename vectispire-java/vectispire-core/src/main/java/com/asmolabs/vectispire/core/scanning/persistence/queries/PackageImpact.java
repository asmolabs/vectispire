package com.asmolabs.vectispire.core.scanning.persistence.queries;

/**
 * What one package amounts to across everything the caller may see.
 *
 * @param anyPurl any purl recorded for the package, used only to name its ecosystem — every
 *     purl of a given package agrees on the prefix that decides it
 * @param distinctRepositories how many repositories hold this package, and
 * @param distinctContainers how many images do. <b>Kept apart rather than summed here</b>
 *     because that is how the database can count them: a scan names one or the other, never
 *     both, so two {@code count(distinct)} over the two nullable columns add up to the number
 *     of distinct targets without a portable way to say "either of these two columns". The
 *     caller adds them.
 * @param maxCvss null when no finding for this package carries a score, which is not zero:
 *     zero is a score, and the caller decides what an absent one means
 */
public record PackageImpact(
        String packageName,
        String anyPurl,
        long distinctRepositories,
        long distinctContainers,
        long directUsages,
        long transitiveUsages,
        long distinctCves,
        Double maxCvss) {

    /** The targets this package reaches — a repository and an image both count as one. */
    public long distinctTargets() {
        return distinctRepositories + distinctContainers;
    }
}

package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Why a measurement has no data — a closed set (decision 0032 §6), declared in the order a headline
 * picks: when repositories lack data for different reasons, the measurement names the first of them
 * here, and each repository's own reason is in the evidence.
 */
public enum NoDataReason {
    /** The project has no repository: "every one of zero repositories passes" is the vacuous truth refused. */
    NO_REPOSITORY,
    /** A repository has no scan or import in which the scope produced, at any age. */
    NEVER_EXAMINED,
    /**
     * The step or plugin was absent in every scan within the age — did not look, not found nothing. Also
     * a coverage report within the age that counted no branch, for a rule on branches: it did not count
     * them, which is not 0 of 0.
     */
    STEP_ABSENT,
    /**
     * The plugin was refused in the newest scan within the age where it did not produce, and produced in
     * none: its manifest declares no signer, the executor requires one, and the governor waived nothing
     * (decision 0017 §9.1). Not a tool that found nothing — a tool nobody started; the line says why, so
     * that the answer is to sign the image or to record the waiver, not to wait for the next scan.
     */
    PLUGIN_UNSIGNED,
    /**
     * The same, refused because the signer its manifest declares did not verify the image — another
     * signer, no signature, or a registry that did not answer cosign.
     */
    PLUGIN_SIGNATURE_UNVERIFIED,
    /**
     * The same, refused because the registry of its image would not let cosign read the signature —
     * no credentials held for it, or the ones held refused. Not "unverified": nothing was read, and the
     * answer is the executor's Docker configuration, not the image or its signer. Thirty-nine
     * characters: the measurement's {@code reason} column holds forty.
     */
    PLUGIN_REGISTRY_AUTHENTICATION_REQUIRED,
    /**
     * The analysis produced, on a tree none — or not all — of whose source languages it reads: the
     * built-in SAST or quality step whose Semgrep rules read none of some source language the scan's
     * census found ({@link SourceLanguages}), or a plugin that produced on a tree holding none of the
     * languages its manifest declares. Nothing found, because nothing was read.
     */
    LANGUAGE_NOT_ANALYSED,
    /** The scans within the age predate {@code examined_types}: whether the step ran is unknown. */
    EXAMINATION_UNRECORDED,
    /**
     * The scan the analysis produced in did not record its tree's languages (no whole census: a scan
     * from before V57, a walk stopped at its bound, an agent older than the census), or not the
     * languages its analysis reads (the Semgrep rules of a scan from before V58, a plugin manifest no
     * longer known): whether it read the tree is unknown.
     */
    LANGUAGES_UNRECORDED,
    /**
     * A presence rule, on a repository whose newest analysed scan no longer holds its SBOM — the payload
     * retention purged it — and whose inventory lists no component: whether the packages are there,
     * nothing recorded. Not "absent", which would answer "not used" for a library nobody looked for.
     */
    INVENTORY_ABSENT,
    /**
     * A declared package is in the SBOM, and the SBOM states no version for any of its occurrences —
     * Syft writes {@code UNKNOWN} where a Maven version comes from a parent or a BOM it does not
     * resolve. The package is there; which version it is, nobody recorded. Not "not an allowed
     * version", which would answer "no" for a module that is present.
     */
    VERSION_UNRECORDED,
    /**
     * A coverage rule scoped to packages, on an import accepted before imports kept their packages (V71):
     * the report was never read package by package, and only importing it again can tell. Never the
     * report's totals in the scope's place, which would be a figure over packages the scope leaves out.
     */
    PACKAGES_UNRECORDED,
    /**
     * A coverage rule scoped to packages, on an import whose packages were not kept — more than the
     * limit, a path that could not be stored whole, or counts that did not add up to the totals; the
     * evidence says which.
     */
    PACKAGES_NOT_KEPT,
    /**
     * A coverage rule scoped to packages, and none of the report's packages is in the scope. Not 0 %,
     * and not 100 %: nothing in the scope was counted, which may be a scope written against another
     * layout than the report's — the evidence names how many packages there were.
     */
    SCOPE_MATCHES_NOTHING,
    /** The newest scan or import in which the scope produced is older than the maximum age. */
    STALE,
    /** A plugin was not applicable on every repository: a line passed by a tool that looked at nothing is refused. */
    NOT_APPLICABLE_ANYWHERE,
    /** No suite of the newest test report matched the rule's pattern. */
    SUITE_NOT_FOUND,
    /** The suites that matched ran nothing, skipped ones not counted. */
    NO_TEST_RAN;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Optional<NoDataReason> ofStored(String value) {
        return Arrays.stream(values()).filter(reason -> reason.wireName().equals(value)).findFirst();
    }
}

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

package com.asmolabs.vectispire.common.domain.owasp;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Where this product's findings land in the OWASP Top 10, and — more to the point — where they
 * cannot.
 *
 * <h2>Why a rule and not a model</h2>
 *
 * <p>The Top 10 report this sits beside is written by the configured model: it reads the backlog
 * and produces prose. That is worth having and it is <b>not evidence</b>. An assessor asked to
 * accept a document cannot accept one whose content depends on which model answered, and a
 * category that came out green last quarter and amber this one has told them nothing about the
 * estate.
 *
 * <p>So this maps findings to categories by rule, from the finding's type alone, and every
 * mapping below is one sentence an assessor can check. Where no rule applies the answer is
 * <em>not covered</em>, never a guess. A mapping that placed a finding by matching substrings in
 * a rule identifier would be reproducible and still a guess dressed as a rule.
 *
 * <h2>Four states, because two would lie</h2>
 *
 * <p><b>A category with no findings and a category nothing looks at produce the same green.</b>
 * That is the defect this whole record exists to remove, and it is the same one the freshness
 * window removed from the compliance matrix and the rule-coverage banner removed from the quality
 * screen. Seven of the ten categories are <em>not covered</em> by any scanner here, and saying so
 * is the single most useful thing this grid does.
 */
public final class OwaspCoverage {

    private OwaspCoverage() {}

    /** The 2021 edition, which is the one every audit questionnaire still asks about. */
    public static final Map<String, String> CATEGORIES = categories();

    private static Map<String, String> categories() {
        Map<String, String> titles = new LinkedHashMap<>();
        titles.put("A01", "Broken Access Control");
        titles.put("A02", "Cryptographic Failures");
        titles.put("A03", "Injection");
        titles.put("A04", "Insecure Design");
        titles.put("A05", "Security Misconfiguration");
        titles.put("A06", "Vulnerable and Outdated Components");
        titles.put("A07", "Identification and Authentication Failures");
        titles.put("A08", "Software and Data Integrity Failures");
        titles.put("A09", "Security Logging and Monitoring Failures");
        titles.put("A10", "Server-Side Request Forgery");
        // **`unmodifiableMap` et non `Map.copyOf`.** La seconde ne conserve pas l'ordre
        // d'insertion, et son itération est salée par JVM : la grille sortait dans l'ordre du
        // standard une exécution sur deux. C'est une question de questionnaire, pas de goût — on
        // lit A01 puis A02, et une grille mélangée se relit à chaque ligne.
        return java.util.Collections.unmodifiableMap(titles);
    }

    /**
     * What this deployment can say about one category.
     *
     * <p>Ordered from what needs attention to what does not, so a sort puts the actionable first —
     * and puts <em>not covered</em> above <em>nothing found</em>, which is the ordering an
     * assessment cares about and a dashboard usually gets backwards.
     */
    public enum State {
        /** A scanner covers it and found things. */
        FINDINGS,
        /**
         * A scanner covers it and has not looked at this estate.
         *
         * <p>Switched off, or — for code analysis — running without a rule that reaches the
         * languages present. Distinct from the next one: here the product could answer and has
         * not been allowed to.
         */
        NOT_MEASURED,
        /**
         * <b>No scanner here can produce a finding in this category at all.</b>
         *
         * <p>A property of the product, not of the estate. Nothing in Vectispire detects broken
         * access control or insecure design; a grid that showed those green would be claiming a
         * clean bill of health over an examination that never happened.
         */
        NOT_COVERED,
        /** A scanner covers it, looked, and found nothing. */
        NO_FINDING
    }

    /**
     * The finding types that place a finding in a category, by rule.
     *
     * <p>Each entry is one defensible sentence:
     *
     * <ul>
     *   <li><b>A05</b> ← infrastructure-as-code checks. Checkov's whole subject is deployment
     *       misconfiguration, which is the category's whole subject.
     *   <li><b>A06</b> ← known vulnerabilities in dependencies, and components past their support
     *       window. "Vulnerable <em>and outdated</em>" names both halves.
     *   <li><b>A07</b> ← exposed secrets. CWE-798, hard-coded credentials, is this category's
     *       entry; a hard-coded <em>cryptographic key</em> would belong to A02 instead, and
     *       nothing in a secret scanner's output says which of the two a match is. One category
     *       rather than both: a finding counted twice inflates the only number here that matters.
     * </ul>
     *
     * <p><b>Code analysis places nothing, and that is the honest state today.</b> A Semgrep rule
     * may declare its OWASP category in its own metadata; this product does not read that
     * metadata yet, so no code finding can be placed by rule — and placing them by guessing at
     * rule identifiers is exactly what this class refuses to do.
     */
    private static final Map<FindingType, String> BY_TYPE = Map.of(
            FindingType.IAC, "A05",
            FindingType.VULNERABILITY, "A06",
            FindingType.EOL, "A06",
            FindingType.SECRET, "A07");

    /** The category a finding of this type belongs to, or nothing when no rule places it. */
    public static Optional<String> categoryOf(FindingType type) {
        return Optional.ofNullable(BY_TYPE.get(type));
    }

    /**
     * What the deployment measures, as opposed to what it found.
     *
     * @param scanned a scan has completed somewhere in the caller's estate. Without one, every
     *     covered category is unmeasured rather than clean
     * @param endOfLifeEnabled whether components past support are detected
     * @param codeAnalysisReaches code analysis runs <em>and</em> a rule reaches the languages
     *     present. Both halves matter: rules that reach nothing find nothing, which is not the
     *     same sentence as "there is nothing"
     * @param openByType open findings per type, however they were counted
     */
    public record Measurement(
            boolean scanned,
            boolean endOfLifeEnabled,
            boolean codeAnalysisReaches,
            Map<FindingType, Long> openByType) {}

    /**
     * @param findings how many open findings this category holds; zero unless {@code state} is
     *     {@link State#FINDINGS}
     * @param because one sentence saying why the state is what it is, meant to be quoted
     */
    public record CoverageLine(String id, String title, State state, long findings, String because) {}

    /**
     * @param covered how many of the ten any scanner here can speak to at all. <b>Read this
     *     before the rest</b>: it is the grid's own coverage, and the figure an assessment starts
     *     from
     */
    public record Grid(List<CoverageLine> lines, int covered, int withFindings, int unmeasured) {}

    /** The grid, in the standard's own order — the order a questionnaire asks the questions in. */
    public static Grid assess(Measurement measurement) {
        List<CoverageLine> lines = CATEGORIES.entrySet().stream()
                .map(category -> line(category.getKey(), category.getValue(), measurement))
                .toList();

        return new Grid(
                lines,
                (int) lines.stream().filter(line -> line.state() != State.NOT_COVERED).count(),
                (int) lines.stream().filter(line -> line.state() == State.FINDINGS).count(),
                (int) lines.stream().filter(line -> line.state() == State.NOT_MEASURED).count());
    }

    private static CoverageLine line(String id, String title, Measurement measurement) {
        List<FindingType> types = BY_TYPE.entrySet().stream()
                .filter(entry -> entry.getValue().equals(id))
                .map(Map.Entry::getKey)
                .toList();

        if (types.isEmpty()) {
            return new CoverageLine(id, title, State.NOT_COVERED, 0,
                    "No scanner in this deployment produces a finding in this category.");
        }
        if (!measurement.scanned()) {
            return new CoverageLine(id, title, State.NOT_MEASURED, 0,
                    "Nothing has been scanned yet, so no finding of this category could exist.");
        }

        // **A type that is switched off measures nothing, and its zero is not a result.** End of
        // life is the case that made this explicit: turning detection off leaves existing findings
        // open rather than resolving them, precisely so that "we stopped looking" never reads as
        // "it is fixed". The same sentence belongs here.
        List<FindingType> measured = types.stream().filter(type -> measures(type, measurement)).toList();
        if (measured.isEmpty()) {
            return new CoverageLine(id, title, State.NOT_MEASURED, 0, whyUnmeasured(types));
        }

        long findings = measured.stream()
                .mapToLong(type -> measurement.openByType().getOrDefault(type, 0L))
                .sum();

        return findings > 0
                ? new CoverageLine(id, title, State.FINDINGS, findings, "Open findings placed here by rule.")
                : new CoverageLine(id, title, State.NO_FINDING, 0,
                        "Scanned by " + names(measured) + ", with nothing open.");
    }

    private static boolean measures(FindingType type, Measurement measurement) {
        return switch (type) {
            case EOL -> measurement.endOfLifeEnabled();
            case SAST -> measurement.codeAnalysisReaches();
            default -> true;
        };
    }

    private static String whyUnmeasured(List<FindingType> types) {
        return types.contains(FindingType.SAST)
                ? "Code analysis is off, or no installed rule reaches the languages in this estate."
                : "Detection is switched off for " + names(types) + ", so this category is not measured.";
    }

    private static String names(List<FindingType> types) {
        return String.join(", ", types.stream().map(FindingType::wireName).toList());
    }
}

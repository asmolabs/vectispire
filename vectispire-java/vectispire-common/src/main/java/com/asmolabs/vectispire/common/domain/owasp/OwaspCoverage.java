package com.asmolabs.vectispire.common.domain.owasp;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

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
 * screen. Most of the ten are <em>not covered</em> by anything here, and saying so is the single
 * most useful thing this grid does.
 *
 * <p><b>How many is "most" is a property of the deployment, not of this class.</b> Four types
 * place findings by rule, and beyond them the installed code-analysis rules cover whatever their
 * authors declared — so an instance that installs the upstream corpus speaks to more categories
 * than one running on the bundled rule alone. That is the honest shape of the answer: the grid
 * reports what this installation can look at, and a number written into this comment would stop
 * being true the first time somebody uploaded a rule set.
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
        // **`unmodifiableMap` and not `Map.copyOf`.** The latter does not keep insertion order,
        // and its iteration is salted per JVM: the grid came out in the standard's order one run in
        // two. This is a matter of the questionnaire, not of taste — one reads A01 then A02, and a
        // shuffled grid has to be re-read line by line.
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
     * <p><b>Code analysis is placed elsewhere, and by the same standard.</b> It has no entry
     * here because its category is not a property of the type: one Semgrep rule finds injections
     * and another finds server-side request forgery. Each rule declares its own category in its
     * {@code metadata.owasp}, that declaration travels with the finding, and
     * {@link OwaspTag} reads it. Reading an author's declaration is not guessing; placing a
     * finding by matching substrings in a rule identifier would be, which is what this class
     * still refuses to do.
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
     * The one type whose findings carry their category on the issue rather than in the type: code
     * analysis, whose rules declare it ({@link OwaspTag}). The grid counts its findings by that column
     * and no other type's — a plugin's or an import's finding carrying a category is not placed.
     */
    public static final FindingType DECLARES_ITS_CATEGORY = FindingType.SAST;

    /** The types {@link #categoryOf} places in this category — empty for one only code analysis reaches. */
    public static Set<FindingType> typesPlacedIn(String category) {
        return BY_TYPE.entrySet().stream()
                .filter(entry -> entry.getValue().equals(category))
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    /**
     * The types {@link #categoryOf} places somewhere — every category's {@link #typesPlacedIn}, together.
     * With {@link #DECLARES_ITS_CATEGORY} declaring one of {@link #CATEGORIES}, they are what {@link
     * #placementOf} places at all: the backlog's {@code owasp_category=any}, the list a week's total opens.
     */
    public static Set<FindingType> typesPlacedAnywhere() {
        return Set.copyOf(BY_TYPE.keySet());
    }

    /**
     * Where one issue lands in the Top 10, by the grid's placement and nothing else: its type's
     * category, or for code analysis the category its rule declared.
     *
     * <p><b>Placement, not measurement.</b> The grid also asks whether a category is measured — end
     * of life switched on, a rule reaching the estate's languages — and counts nothing where it is not.
     * Those are settings of the moment; a reading of the past (the weekly flows, a drill-down to a
     * category) knows the issue and not the settings that ruled the day it was found, so it places the
     * issue and says no more. The backlog's {@code owasp_category} filter selects the same set.
     *
     * @param declaredCategory the issue's {@code owasp_category}, read for code analysis only
     */
    public static Optional<String> placementOf(FindingType type, String declaredCategory) {
        Optional<String> byType = categoryOf(type);
        if (byType.isPresent()) {
            return byType;
        }
        return type == DECLARES_ITS_CATEGORY && declaredCategory != null && CATEGORIES.containsKey(declaredCategory)
                ? Optional.of(declaredCategory)
                : Optional.empty();
    }

    /**
     * One category over several targets, from each target's recorded line — the weekly record kept per
     * target, read for a project, a solution or a reader's estate. The lines may be per target or already
     * summed per state; the answer is the same.
     *
     * <p><b>The live grid's answer for the same targets</b>, which is what makes a heatmap's last column
     * agree with the grid beside it. The grid counts every visible target's open findings once one of
     * them has been scanned, so: a category some target measured ({@link State#FINDINGS} or {@link
     * State#NO_FINDING} — a scanned target's line, the reading's settings being the estate's) counts every
     * line's findings, those of a target never scanned included ({@link #unscanned}), and reads {@code
     * FINDINGS} when the sum is above zero, {@code NO_FINDING} otherwise; a category nothing here covers is
     * {@link State#NOT_COVERED} for every target, since that is a property of the deployment; anything
     * else is {@link State#NOT_MEASURED}, and counts nothing — a target never scanned holds findings the
     * grid does not count until something visible beside it is scanned.
     *
     * @return empty when no target was recorded — never a state invented for nothing
     */
    public static Optional<Split> acrossTargets(String id, java.util.Collection<Split> perTarget) {
        if (perTarget.isEmpty()) {
            return Optional.empty();
        }
        boolean measured = perTarget.stream()
                .anyMatch(line -> line.state() == State.FINDINGS || line.state() == State.NO_FINDING);
        if (measured) {
            long open = perTarget.stream().mapToLong(Split::open).sum();
            long settled = perTarget.stream().mapToLong(Split::settled).sum();
            return Optional.of(new Split(id, open > 0 ? State.FINDINGS : State.NO_FINDING, open, settled));
        }
        return Optional.of(new Split(id,
                perTarget.stream().allMatch(line -> line.state() == State.NOT_COVERED) ? State.NOT_COVERED : State.NOT_MEASURED,
                0, 0));
    }

    /**
     * The lines of a target nothing has scanned, from its grid read as if it had been.
     *
     * <p><b>Not measured, with the findings the grid would count.</b> The live grid reads a whole visible
     * estate: one scanned target makes it measured, and from then on it counts every target's open
     * findings — a target never scanned among them. Recorded per target, such a target used to read not
     * measured with nothing, and an estate's sum then fell short of the grid shown beside it. Its state
     * stays {@link State#NOT_MEASURED}, since nothing looked at it, and its counts are kept: {@link
     * #acrossTargets} adds them where something measured the category, and drops them where nothing did,
     * which is what the grid does. A category no scanner covers, or one unmeasured by the settings, counts
     * nothing already.
     *
     * @param asIfScanned the target's split, read with the estate measured
     */
    public static List<Split> unscanned(List<Split> asIfScanned) {
        return asIfScanned.stream()
                .map(line -> line.state() == State.FINDINGS || line.state() == State.NO_FINDING
                        ? new Split(line.id(), State.NOT_MEASURED, line.open(), line.settled())
                        : line)
                .toList();
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
     * @param declaredByRules the categories the <em>installed</em> rules declare. <b>This is what
     *     makes an empty category honest.</b> Counting only the categories that already have a
     *     finding would make "nothing found here" indistinguishable from "no rule looks here",
     *     which is the one distinction this whole record exists to draw — and it would flip a
     *     category from covered to uncovered the day its last finding is fixed
     * @param openByCategory open code findings per declared category. Only categories in
     *     {@code declaredByRules} are read from it
     */
    public record Measurement(
            boolean scanned,
            boolean endOfLifeEnabled,
            boolean codeAnalysisReaches,
            Map<FindingType, Long> openByType,
            Set<String> declaredByRules,
            Map<String, Long> openByCategory) {

        /** The reading a caller that knows nothing of code analysis gets: the previous shape. */
        public Measurement(
                boolean scanned,
                boolean endOfLifeEnabled,
                boolean codeAnalysisReaches,
                Map<FindingType, Long> openByType) {
            this(scanned, endOfLifeEnabled, codeAnalysisReaches, openByType, Set.of(), Map.of());
        }

        public Measurement {
            declaredByRules = declaredByRules == null ? Set.of() : Set.copyOf(declaredByRules);
            openByCategory = openByCategory == null ? Map.of() : Map.copyOf(openByCategory);
        }
    }

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

    /**
     * One category of one grid, with the open findings whose triage is settled counted apart.
     *
     * @param state the state the grid reports — the one read without the settled findings, which is
     *     the grid this product shows. A category whose every open finding is accepted reads
     *     {@link State#NO_FINDING} here, and its {@code settled} says what that cost
     * @param open open findings whose triage is not settled: the grid's own figure
     * @param settled open findings whose triage is settled — accepted, not applicable, a false
     *     positive. <b>Kept apart rather than dropped or added in</b>: dropped, an accepted risk
     *     vanishes from the record; added in, it reads as work still to do
     */
    public record Split(String id, State state, long open, long settled) {}

    /**
     * The two readings of one estate side by side: {@code unsettled} counted as the grid counts,
     * {@code all} with the settled findings included, both from {@link #assess}.
     *
     * <p><b>The difference of two grids, and not a third rule.</b> Settled findings are subject to
     * the same placement as the others — a category nothing measures counts none of either — and
     * computing them by a separate path is how the two figures would come to disagree about which
     * categories a finding lands in. Never below zero: the two readings are separate statements, and a
     * finding settled between them would otherwise be counted as minus one.
     */
    public static List<Split> split(Grid unsettled, Grid all) {
        Map<String, Long> withSettled = new LinkedHashMap<>();
        all.lines().forEach(line -> withSettled.put(line.id(), line.findings()));
        return unsettled.lines().stream()
                .map(line -> new Split(line.id(), line.state(), line.findings(),
                        Math.max(0, withSettled.getOrDefault(line.id(), 0L) - line.findings())))
                .toList();
    }

    private static CoverageLine line(String id, String title, Measurement measurement) {
        List<FindingType> types = BY_TYPE.entrySet().stream()
                .filter(entry -> entry.getValue().equals(id))
                .map(Map.Entry::getKey)
                .toList();

        // **Two ways in, and they are not the same question.** A type covers a category by rule,
        // for every estate. Code analysis covers one because a rule somebody installed says so —
        // so the answer differs from one deployment to the next, and it is read rather than
        // assumed.
        boolean declared = measurement.declaredByRules().contains(id);

        if (types.isEmpty() && !declared) {
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
        boolean codeMeasured = declared && measurement.codeAnalysisReaches();

        if (measured.isEmpty() && !codeMeasured) {
            return new CoverageLine(id, title, State.NOT_MEASURED, 0, whyUnmeasured(types, declared));
        }

        long findings = measured.stream()
                .mapToLong(type -> measurement.openByType().getOrDefault(type, 0L))
                .sum()
                + (codeMeasured ? measurement.openByCategory().getOrDefault(id, 0L) : 0L);

        return findings > 0
                ? new CoverageLine(id, title, State.FINDINGS, findings, "Open findings placed here by rule.")
                : new CoverageLine(id, title, State.NO_FINDING, 0, "Scanned by " + what(measured, codeMeasured)
                        + ", with nothing open.");
    }

    private static boolean measures(FindingType type, Measurement measurement) {
        return switch (type) {
            case EOL -> measurement.endOfLifeEnabled();
            default -> true;
        };
    }

    /**
     * Why a covered category is nonetheless unmeasured — naming the half that is off.
     *
     * <p>Both halves can be off at once, and saying only one of them would send somebody to
     * switch on a detector that was already running.
     */
    private static String whyUnmeasured(List<FindingType> types, boolean declared) {
        // **Three causes, all three named.** On a fresh instance the commonest is the second —
        // only the shipped rule is installed — and naming just one would send somebody to switch
        // back on a detector that was already running.
        String code = "code analysis is off, or only the rule this product ships is installed, or none "
                + "of the installed rules reaches the languages in this estate";
        if (types.isEmpty()) {
            return capitalise(code) + ".";
        }
        String detectors = "detection is switched off for " + names(types);
        return capitalise(declared ? detectors + ", and " + code : detectors) + ", so this category is not measured.";
    }

    private static String what(List<FindingType> measured, boolean codeMeasured) {
        if (measured.isEmpty()) {
            return "code analysis";
        }
        return codeMeasured ? names(measured) + ", code analysis" : names(measured);
    }

    private static String capitalise(String sentence) {
        return Character.toUpperCase(sentence.charAt(0)) + sentence.substring(1);
    }

    private static String names(List<FindingType> types) {
        return String.join(", ", types.stream().map(FindingType::wireName).toList());
    }
}

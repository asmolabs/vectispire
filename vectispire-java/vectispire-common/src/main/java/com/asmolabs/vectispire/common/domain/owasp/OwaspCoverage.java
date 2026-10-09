package com.asmolabs.vectispire.common.domain.owasp;

import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
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
         * <p>Switched off; or a target in scope whose latest finished scan did not examine it — never
         * scanned, failed, the step absent ({@link Evidence}); or — for code analysis — no installed rule
         * declaring it written for the languages of a repository in scope. Distinct from the next one:
         * here the product could answer and has not been allowed to.
         */
        NOT_MEASURED,
        /**
         * <b>No scanner here can produce a finding in this category at all.</b>
         *
         * <p>A property of the product, not of the estate. Nothing in Vectispire detects broken
         * access control or insecure design; a grid that showed those green would be claiming a
         * clean bill of health over an examination that never happened. A target's own line also
         * reads so where nothing here examines that kind of target for it — an image, for secrets
         * ({@link #assessTarget}).
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
     * Whether a target's scans can examine it for this type at all — by what its kind of scan runs, not
     * by what one scan did.
     *
     * <p><b>An image's scan runs the dependency step alone</b> ({@code ScanDispatcher}'s image steps): its
     * SBOM gives the vulnerabilities, the components past support and the licences, and nothing reads
     * an image for committed secrets, for infrastructure code or with code analysis. Asking an image for
     * them and reading "not examined" would hold a project's every category unmeasured for owning an
     * image; reading "examined" was the defect this replaces — an image-only scope showed A05 and A07 as
     * clean. {@code ScanDispatcherTest} keeps the image's steps what this assumes.
     */
    public static boolean examinable(FindingType type, ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository ignored -> true;
            case ScanTarget.Container ignored -> type == FindingType.VULNERABILITY || type == FindingType.EOL
                    || type == FindingType.LICENSE;
        };
    }

    /**
     * What one target's newest finished scan says it was examined for — the evidence a category's
     * "nothing found" rests on (decision 0007: absent is not empty).
     *
     * <p><b>A scan having run is not the question; which of its steps produced is.</b> The grid used to
     * read a category measured as soon as any target in scope had a scan, so an image-only project showed
     * the secrets and misconfiguration categories as clean — an image's scan looks for neither — and a
     * repository whose secret step failed showed A07 clean on the strength of the steps that did not.
     * The scan records the types whose step produced ({@code examined_types}, decision 0032 §6), and that
     * record is what is read here.
     *
     * <p><b>The newest finished scan, as the gate reads it</b> ({@link Observation}): a running scan has
     * changed nothing in the backlog, and a failed one examined nothing that can be relied on — the
     * backlog its predecessor left is still there, and it is counted, but it is no observation of the code
     * as it is.
     *
     * @param observation the newest finished scan's status, as {@link Observation#of} reads it
     * @param examined the types that scan's steps produced; empty unless {@code observation} is {@link
     *     Observation#OK} and the scan recorded them — a scan from before the record says nothing
     * @param analysed the languages of the target's tree that its scan's code-analysis rules read: the
     *     census's languages intersected with the rules' ({@code sast_languages}). Empty when either side
     *     was not recorded, which is not the empty set: "nobody counted" is not "no rule reads it"
     * @param codeReaches the categories declared by an installed rule written for one of {@code analysed};
     *     empty exactly when {@code analysed} is
     */
    public record Evidence(
            ScanTarget target,
            Observation observation,
            Optional<Set<FindingType>> examined,
            Optional<Set<Language>> analysed,
            Optional<Set<String>> codeReaches) {

        public Evidence {
            examined = observation == Observation.OK ? examined.map(Set::copyOf) : Optional.empty();
            analysed = analysed.map(Set::copyOf);
            codeReaches = analysed.isEmpty() ? Optional.empty() : codeReaches.map(Set::copyOf).or(() -> Optional.of(Set.of()));
        }

        /** A target with no finished scan. */
        public static Evidence neverScanned(ScanTarget target) {
            return new Evidence(target, Observation.NEVER_SCANNED, Optional.empty(), Optional.empty(), Optional.empty());
        }

        /**
         * The evidence of one finished scan.
         *
         * <p><b>The rules' categories are today's, narrowed to the languages the scan's own rules read.</b>
         * The scan records which languages its rule set read, not the set itself; a category is placed
         * from the installed rules of that language. A set swapped since for one of the same languages
         * declaring other categories would be read with the new declarations until the next scan, which
         * the next scan corrects — and a language the scan's rules did not read is never credited, which
         * is the direction that would let a category read clean.
         *
         * @param detected the languages the scan's census found in the tree; empty when unrecorded
         * @param sastRules the languages its code-analysis rules read; empty when unrecorded
         * @param declaredByLanguage the categories the installed rules of each language declare
         */
        public static Evidence of(
                ScanTarget target,
                Observation observation,
                Optional<Set<FindingType>> examined,
                Optional<Set<Language>> detected,
                Optional<Set<Language>> sastRules,
                Map<Language, Set<String>> declaredByLanguage) {
            Optional<Set<Language>> analysed = detected.isEmpty() || sastRules.isEmpty()
                    ? Optional.empty()
                    : Optional.of(detected.get().stream().filter(sastRules.get()::contains)
                            .collect(java.util.stream.Collectors.toUnmodifiableSet()));
            Optional<Set<String>> reaches = analysed.map(languages -> languages.stream()
                    .flatMap(language -> declaredByLanguage.getOrDefault(language, Set.of()).stream())
                    .collect(java.util.stream.Collectors.toUnmodifiableSet()));
            return new Evidence(target, observation, examined, analysed, reaches);
        }

        boolean examinedFor(FindingType type) {
            return examined.map(types -> types.contains(type)).orElse(false);
        }
    }

    /**
     * Why one target was not examined for a category, for the sentence that says how many were not.
     * Declared in the order the sentence names them.
     */
    private enum Gap {
        NEVER_SCANNED("never finished a scan"),
        LAST_SCAN_FAILED("whose latest scan failed"),
        UNRECORDED("whose latest scan predates the record of what it examined"),
        STEP_ABSENT("whose latest scan did not complete that step"),
        LANGUAGES_UNRECORDED("whose latest scan did not record its languages, or its rules'"),
        NO_RULE_FOR_ITS_LANGUAGES("in whose languages no installed rule declares this category");

        private final String words;

        Gap(String words) {
            this.words = words;
        }
    }

    /** Where a category's examination comes from, for one grid: the types placed in it, or code analysis. */
    private sealed interface Source {

        /** @param types the types placed in the category that the settings measure */
        record Types(List<FindingType> types) implements Source {}

        record Code(String category) implements Source {}

        default boolean appliesTo(ScanTarget target) {
            return switch (this) {
                case Types placed -> placed.types().stream().anyMatch(type -> examinable(type, target));
                case Code ignored -> target instanceof ScanTarget.Repository;
            };
        }

        /** Why this target was not examined for it, or empty when it was. */
        default Optional<Gap> gapOf(Evidence evidence) {
            switch (evidence.observation()) {
                case OK -> {}
                case LAST_SCAN_FAILED -> {
                    return Optional.of(Gap.LAST_SCAN_FAILED);
                }
                // IN_PROGRESS does not reach here — the evidence is the newest *finished* scan — and would
                // be no examination if it did.
                default -> {
                    return Optional.of(Gap.NEVER_SCANNED);
                }
            }
            if (evidence.examined().isEmpty()) {
                return Optional.of(Gap.UNRECORDED);
            }
            return switch (this) {
                // Every type this target can be examined for: A06 is "vulnerable *and* outdated", and an
                // end-of-life lookup that failed leaves the second half unlooked at.
                case Types placed -> placed.types().stream()
                                .filter(type -> examinable(type, evidence.target()))
                                .allMatch(evidence::examinedFor)
                        ? Optional.empty()
                        : Optional.of(Gap.STEP_ABSENT);
                case Code code -> !evidence.examinedFor(FindingType.SAST)
                        ? Optional.of(Gap.STEP_ABSENT)
                        : evidence.codeReaches().isEmpty()
                                ? Optional.of(Gap.LANGUAGES_UNRECORDED)
                                : evidence.codeReaches().get().contains(code.category())
                                        ? Optional.empty()
                                        : Optional.of(Gap.NO_RULE_FOR_ITS_LANGUAGES);
            };
        }
    }

    /**
     * One category over several targets, from each target's recorded line — the weekly record kept per
     * target, read for a project, a solution or a reader's estate. The lines may be per target or already
     * summed per state; the answer is the same.
     *
     * <p><b>The live grid's answer for the same targets</b> ({@link #assess}), which is what makes a
     * heatmap's last column agree with the grid beside it — the grid of a scope is the fold of its
     * targets' lines ({@link #assessTarget}), by construction and by test:
     *
     * <ul>
     *   <li>open findings anywhere make it {@link State#FINDINGS}, with every line's counts — an open
     *       finding is a fact whatever examined it;
     *   <li>otherwise a line {@link State#NOT_COVERED} is a target nothing here can examine for it — an
     *       image, for secrets — and is left aside; a category nothing in this deployment covers reads so
     *       on every line;
     *   <li>of the rest, one {@link State#NOT_MEASURED} line makes it {@link State#NOT_MEASURED}: a scope
     *       examined in part has not been examined, and "nothing found" over half of it is the false
     *       green this rule removes;
     *   <li>every remaining line {@link State#NO_FINDING} makes it {@link State#NO_FINDING};
     *   <li>no line left at all reads {@link State#NOT_MEASURED} for a category a type places — no target
     *       here can be examined for it, which is a property of the scope, the product examining it on
     *       repositories — and {@link State#NOT_COVERED} for one only code analysis reaches, the lines
     *       not saying whether a rule declared it that week.
     * </ul>
     *
     * <p>Lines recorded before the evidence was read per target — a never-scanned target kept {@link
     * State#NOT_MEASURED} with the findings the grid would count — fold the same way: their findings are
     * counted, as the grid now counts them.
     *
     * @return empty when no target was recorded — never a state invented for nothing
     */
    public static Optional<Split> acrossTargets(String id, java.util.Collection<Split> perTarget) {
        if (perTarget.isEmpty()) {
            return Optional.empty();
        }
        long open = perTarget.stream().mapToLong(Split::open).sum();
        long settled = perTarget.stream().mapToLong(Split::settled).sum();
        if (open > 0) {
            return Optional.of(new Split(id, State.FINDINGS, open, settled));
        }
        List<State> applicable = perTarget.stream()
                .map(Split::state)
                .filter(state -> state != State.NOT_COVERED)
                .toList();
        State state;
        if (applicable.isEmpty()) {
            state = typesPlacedIn(id).isEmpty() ? State.NOT_COVERED : State.NOT_MEASURED;
        } else if (applicable.stream().allMatch(line -> line == State.NO_FINDING || line == State.FINDINGS)) {
            state = State.NO_FINDING;
        } else {
            state = State.NOT_MEASURED;
        }
        return Optional.of(new Split(id, state, 0, settled));
    }

    /**
     * What the deployment measures, as opposed to what it found.
     *
     * @param endOfLifeEnabled whether components past support are detected
     * @param codeAnalysisEnabled code analysis runs <em>and</em> more than the rule this product ships is
     *     installed — the deployment's half of the question. Whether a rule reaches <em>this</em> target's
     *     languages is the evidence's ({@link Evidence#codeReaches}): a Python rule declaring A03 says
     *     nothing of a Java repository
     * @param openByType open findings per type, however they were counted
     * @param declaredByRules the categories the <em>installed</em> rules declare. <b>This is what
     *     makes an empty category honest.</b> Counting only the categories that already have a
     *     finding would make "nothing found here" indistinguishable from "no rule looks here",
     *     which is the one distinction this whole record exists to draw — and it would flip a
     *     category from covered to uncovered the day its last finding is fixed
     * @param openByCategory open code findings per declared category. Only categories in
     *     {@code declaredByRules} are read from it
     * @param targets the evidence of every target the counts were read over — one for a target's own
     *     line. A target the counts cover and this omits is a target taken as examined, which is the
     *     false green; the caller hands every one
     */
    public record Measurement(
            boolean endOfLifeEnabled,
            boolean codeAnalysisEnabled,
            Map<FindingType, Long> openByType,
            Set<String> declaredByRules,
            Map<String, Long> openByCategory,
            List<Evidence> targets) {

        public Measurement {
            openByType = openByType == null ? Map.of() : Map.copyOf(openByType);
            declaredByRules = declaredByRules == null ? Set.of() : Set.copyOf(declaredByRules);
            openByCategory = openByCategory == null ? Map.of() : Map.copyOf(openByCategory);
            targets = targets == null ? List.of() : List.copyOf(targets);
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

    /** The grid of a scope, in the standard's own order — the order a questionnaire asks the questions in. */
    public static Grid assess(Measurement measurement) {
        return grid(measurement, false);
    }

    /**
     * One target's own grid — the line the weekly record keeps for it, and what the model-written report
     * is told of a repository.
     *
     * <p><b>One difference from a scope of that one target</b>, and it is what lets a scope's grid be the
     * fold of its targets' ({@link #acrossTargets}): a category the target cannot be examined for at all
     * — an image, for secrets — reads {@link State#NOT_COVERED} here, nothing in this product covering it
     * for that target, so that a fold can leave it aside; a scope holding only such targets reads not
     * measured instead. For a repository the two readings are the same.
     *
     * @param measurement read over this target alone, its {@code targets} its own evidence
     */
    public static Grid assessTarget(Measurement measurement) {
        if (measurement.targets().size() != 1) {
            throw new IllegalArgumentException("A target's grid is read over that one target.");
        }
        return grid(measurement, true);
    }

    private static Grid grid(Measurement measurement, boolean oneTarget) {
        List<CoverageLine> lines = CATEGORIES.entrySet().stream()
                .map(category -> line(category.getKey(), category.getValue(), measurement, oneTarget))
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
     *     {@link State#NO_FINDING} here when it was examined, and its {@code settled} says what that cost
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

    private static CoverageLine line(String id, String title, Measurement measurement, boolean oneTarget) {
        List<FindingType> types = BY_TYPE.entrySet().stream()
                .filter(entry -> entry.getValue().equals(id))
                .map(Map.Entry::getKey)
                .sorted()
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

        // **A type that is switched off measures nothing, and its zero is not a result.** End of
        // life is the case that made this explicit: turning detection off leaves existing findings
        // open rather than resolving them, precisely so that "we stopped looking" never reads as
        // "it is fixed". The same sentence belongs here.
        List<FindingType> measured = types.stream().filter(type -> measures(type, measurement)).toList();
        boolean codeMeasured = declared && measurement.codeAnalysisEnabled();

        if (measured.isEmpty() && !codeMeasured) {
            return new CoverageLine(id, title, State.NOT_MEASURED, 0, whyUnmeasured(types, declared));
        }

        // **An open finding is a fact, whatever examined the target since.** A secret found last week
        // whose step failed this week is still open — absent resolves nothing — and a grid reading
        // "not measured" over it would hide what is known. So findings decide first; the evidence decides
        // only whether a zero means anything.
        long findings = measured.stream()
                .mapToLong(type -> measurement.openByType().getOrDefault(type, 0L))
                .sum()
                + (codeMeasured ? measurement.openByCategory().getOrDefault(id, 0L) : 0L);

        if (findings > 0) {
            return new CoverageLine(id, title, State.FINDINGS, findings, "Open findings placed here by rule.");
        }

        // A category a type places is examined by those types — the code rules declaring it too add
        // their findings to the count, not a second condition to its examination.
        Source source = measured.isEmpty() ? new Source.Code(id) : new Source.Types(measured);
        String what = source instanceof Source.Types placed ? names(placed.types()) : "code analysis";

        if (measurement.targets().isEmpty()) {
            return new CoverageLine(id, title, State.NOT_MEASURED, 0,
                    "Nothing has been scanned yet, so no finding of this category could exist.");
        }
        List<Evidence> applicable = measurement.targets().stream()
                .filter(evidence -> source.appliesTo(evidence.target()))
                .toList();
        if (applicable.isEmpty()) {
            if (oneTarget) {
                return new CoverageLine(id, title, State.NOT_COVERED, 0, source instanceof Source.Types
                        ? "Nothing here examines this kind of target for " + what + ": an image's scan reads its "
                                + "dependencies only."
                        : "Only code analysis places findings here, and it reads repositories, not images.");
            }
            return source instanceof Source.Types
                    ? new CoverageLine(id, title, State.NOT_MEASURED, 0, "No target in this scope can be examined for "
                            + what + ": an image's scan reads its dependencies only, and this scope holds no repository.")
                    : new CoverageLine(id, title, State.NOT_COVERED, 0,
                            "Only code analysis places findings here, and this scope holds no repository for it to read.");
        }

        Map<Gap, Long> gaps = new java.util.EnumMap<>(Gap.class);
        applicable.forEach(evidence -> source.gapOf(evidence)
                .ifPresent(gap -> gaps.merge(gap, 1L, Long::sum)));
        if (gaps.isEmpty()) {
            return new CoverageLine(id, title, State.NO_FINDING, 0, "Scanned by " + what
                    + " — the latest scan of every target it applies to examined it — with nothing open.");
        }
        return new CoverageLine(id, title, State.NOT_MEASURED, 0, unexamined(source, what, applicable.size(), gaps));
    }

    /**
     * "2 of 3 targets…", and why each was not — the sentence an assessor quotes when a category reads not
     * measured over a scope that was scanned.
     */
    private static String unexamined(Source source, String what, int applicable, Map<Gap, Long> gaps) {
        long missing = gaps.values().stream().mapToLong(Long::longValue).sum();
        String noun = source instanceof Source.Types
                ? (applicable == 1 ? "target" : "targets")
                : (applicable == 1 ? "repository" : "repositories");
        String why = gaps.entrySet().stream()
                .map(gap -> gap.getValue() + " " + gap.getKey().words)
                .collect(java.util.stream.Collectors.joining(", "));
        return missing + " of " + applicable + " " + noun + " this category applies to "
                + (missing == 1 ? "was" : "were") + " not examined for it by " + what + " (" + why + "), so a "
                + "zero here would not be a result.";
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
        // **Both causes named.** On a fresh instance the commonest is the second — only the shipped
        // rule is installed — and naming just one would send somebody to switch back on a detector
        // that was already running. Whether a rule reaches a target's languages is not said here: it is
        // the evidence's, target by target, and a scope the rules do not reach says so in its own words.
        String code = "code analysis is off, or only the rule this product ships is installed";
        if (types.isEmpty()) {
            return capitalise(code) + ".";
        }
        String detectors = "detection is switched off for " + names(types);
        return capitalise(declared ? detectors + ", and " + code : detectors) + ", so this category is not measured.";
    }

    private static String capitalise(String sentence) {
        return Character.toUpperCase(sentence.charAt(0)) + sentence.substring(1);
    }

    private static String names(List<FindingType> types) {
        return String.join(", ", types.stream().map(FindingType::wireName).toList());
    }
}

package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule.ComponentVersions;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule.CoverageThreshold;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule.DependencyAnalysis;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule.FindingsThreshold;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule.TestSuitePassed;
import com.asmolabs.vectispire.common.domain.checklists.Measurement.Figure;
import com.asmolabs.vectispire.common.domain.checklists.Measurement.RepositoryEvidence;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.CoverageReport;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Imported;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.IssueCount;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginRun;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginRuns;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginState;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ScanLanguages;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Scanned;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ScopeFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Source;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Suite;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.TestReport;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A rule applied to what the owners recorded about a project (decision 0032 §6) — pure: the facts and
 * the instant in, a {@link Measurement} out.
 *
 * <h2>No data is never a pass</h2>
 *
 * <p>Decision 0007 applied to a line: a repository whose step did not look is not a repository whose
 * step found nothing, and a rule reads the difference from what was recorded. So a project without a
 * repository has no data — every one of zero passes, which is the vacuous truth refused; a step absent
 * in every scan within the age has no data; a scan from before {@code examined_types} has no data,
 * since nothing recorded whether it looked; a plugin not applicable anywhere has no data, since a line
 * passed by a tool that looked at nothing is passed on nothing. One repository without data makes the
 * measurement {@link MeasurementOutcome#NO_DATA}: the line speaks for every repository of its project.
 *
 * <p><b>Thresholds are judged on complete data only.</b> With a repository missing, the counts are the
 * other repositories' — a partial backlog a threshold would pass or fail on figures that are not the
 * project's. The figures are still reported, unjudged; the outcome is {@code NO_DATA}.
 *
 * <h2>The backlog's figures</h2>
 *
 * <p>The counts arrive with settled triage already left out, by the owner's own {@code not in} — so a
 * triage status this version does not know is counted. An issue's state is read the same way: only
 * {@code resolved} is resolved, and a state this version does not know stays open. Unknown is still in
 * the way, never silently settled.
 */
public final class RuleEvaluation {

    private RuleEvaluation() {}

    /** What one scope was on one repository, once the rules have read its facts. */
    sealed interface ScopeState permits Examined, NotApplicable, Missing {}

    /** @param note what the evidence adds to "examined" — which languages were read, for one */
    record Examined(Look look, Optional<String> note) implements ScopeState {

        Examined(Look look) {
            this(look, Optional.empty());
        }
    }

    record NotApplicable(Look look) implements ScopeState {}

    record Missing(NoDataReason reason, Optional<Look> newest, Optional<String> detail) implements ScopeState {

        Missing(NoDataReason reason, Optional<Look> newest) {
            this(reason, newest, Optional.empty());
        }
    }

    public static Measurement evaluate(ChecklistRule rule, MeasurementFacts facts, Instant now) {
        Objects.requireNonNull(rule, "rule");
        Objects.requireNonNull(facts, "facts");
        Objects.requireNonNull(now, "now");
        List<Long> repositories = facts.repositoryIds().stream().distinct().sorted().toList();
        if (repositories.isEmpty()) {
            return new Measurement(MeasurementOutcome.NO_DATA, Optional.of(NoDataReason.NO_REPOSITORY), Optional.empty(),
                    List.of(), List.of(), "No data: the project has no repository, and a line is not passed by none of them.");
        }
        Instant since = now.minus(rule.maxAge());
        return switch (rule) {
            case DependencyAnalysis dependency -> dependencies(dependency, facts, repositories, since);
            case FindingsThreshold findings -> findings(findings, facts, repositories, since);
            case CoverageThreshold coverage -> coverage(coverage, facts, repositories, since);
            case TestSuitePassed tests -> tests(tests, facts, repositories, since);
            case ComponentVersions components -> components(components, facts, repositories, since);
        };
    }

    // ------------------------------------------------------------------ one scope on one repository

    /**
     * What the facts about one scope say of one repository. The order of the questions is the rule: a
     * step that produced within the age is examined, whatever else happened; a scan within the age that
     * recorded its steps without this one says it did not look; one from before the record says
     * nothing; with nothing within the age, an older look is stale, and no look at all is never.
     */
    static ScopeState classify(ScopeFacts facts, Instant since) {
        return switch (facts) {
            case null -> new Missing(NoDataReason.NEVER_EXAMINED, Optional.empty());
            case Scanned scanned -> {
                Optional<Look> newest = scanned.newestProducing();
                if (newest.isPresent() && !newest.get().at().isBefore(since)) {
                    yield new Examined(newest.get());
                }
                if (scanned.recordedWithinAge() > 0) {
                    yield new Missing(NoDataReason.STEP_ABSENT, newest);
                }
                if (scanned.unrecordedWithinAge() > 0) {
                    yield new Missing(NoDataReason.EXAMINATION_UNRECORDED, newest);
                }
                yield new Missing(newest.isPresent() ? NoDataReason.STALE : NoDataReason.NEVER_EXAMINED, newest);
            }
            case PluginRuns runs -> {
                List<PluginRun> within = runs.withinAge().stream()
                        .filter(run -> !run.scan().at().isBefore(since))
                        .sorted(Comparator.comparing((PluginRun run) -> run.scan().at()).reversed())
                        .toList();
                Optional<PluginRun> produced = within.stream().filter(run -> run.state() == PluginState.PRODUCED).findFirst();
                if (produced.isPresent()) {
                    yield new Examined(produced.get().scan());
                }
                // Absent or refused once within the age and never produced: it should have run and did
                // not. That outweighs a "not applicable" beside it — the tree it skipped is not the tree
                // it failed on. The newest of them names the reason: a plugin refused as unsigned last
                // week and crashing today is today's problem.
                Optional<PluginRun> failed = within.stream()
                        .filter(run -> run.state() != PluginState.NOT_APPLICABLE)
                        .findFirst();
                if (failed.isPresent()) {
                    Optional<Look> scan = Optional.of(failed.get().scan());
                    yield switch (failed.get().state()) {
                        case REFUSED_UNSIGNED -> new Missing(NoDataReason.PLUGIN_UNSIGNED, scan, Optional.of("the executor"
                                + " refused the plugin: its manifest declares no signer, a signer is required, and no"
                                + " waiver covers it"));
                        case REFUSED_SIGNATURE_UNVERIFIED -> new Missing(NoDataReason.PLUGIN_SIGNATURE_UNVERIFIED, scan,
                                Optional.of("the executor refused the plugin: the signer its manifest declares did not"
                                        + " verify its image"));
                        default -> new Missing(NoDataReason.STEP_ABSENT, scan);
                    };
                }
                if (!within.isEmpty()) {
                    yield new NotApplicable(within.getFirst().scan());
                }
                // Scans within the age that do not name it ran without it: a plugin missing from a
                // scan's steps is absent (decision 0017).
                if (runs.scansWithinAge() > 0) {
                    yield new Missing(NoDataReason.STEP_ABSENT, Optional.empty());
                }
                yield new Missing(runs.namedBefore() ? NoDataReason.STALE : NoDataReason.NEVER_EXAMINED, Optional.empty());
            }
            case Imported imported -> {
                Optional<Look> newest = imported.newestProducing();
                if (newest.isPresent() && !newest.get().at().isBefore(since)) {
                    yield new Examined(newest.get());
                }
                if (imported.unrecordedWithinAge()) {
                    yield new Missing(NoDataReason.EXAMINATION_UNRECORDED, newest);
                }
                yield new Missing(newest.isPresent() ? NoDataReason.STALE : NoDataReason.NEVER_EXAMINED, newest);
            }
        };
    }

    // ------------------------------------------------------------------ what the analysis read

    /**
     * An examined scope, asked whether its analysis read the tree it produced on — for the scopes whose
     * reach is a set of languages: the built-in SAST and quality steps, which are Semgrep and its rules,
     * and every plugin, which declares the languages it reads. The other scopes are returned as they
     * came: a secret, a misconfiguration or a vulnerable dependency is looked for whatever the code's
     * language, and an import records no language at all.
     *
     * <p><b>Judged on the scan the measurement rests on</b>, by what that scan recorded: its census of
     * the tree, the languages of the rules its task carried, the manifest it named. The rules or the
     * manifest of today would let a set activated after the scan pass it — coverage the scan never had.
     *
     * <p><b>A step that produced on a tree it could not read found nothing because it read nothing</b>
     * — decision 0007 once more, and the line would carry an automatic <i>yes</i> into a signed document.
     * So: unknown languages on either side are {@link NoDataReason#LANGUAGES_UNRECORDED}; for the
     * built-in steps, a source language of the tree ({@link SourceLanguages}) that no rule reads is
     * {@link NoDataReason#LANGUAGE_NOT_ANALYSED}, even when another is read — "static analysis" said of
     * a Java and TypeScript repository whose TypeScript nobody read would be the claim refused. A
     * plugin is a tool chosen for what it declares: it must have read one of the tree's languages, and
     * the evidence names the source languages it does not read, without refusing the line for them —
     * a Dockerfile linter bound to a line must be able to pass on a Java repository.
     */
    static ScopeState read(ToolScope scope, ScopeFacts scoped, ScopeState state, Map<Long, ScanLanguages> languages) {
        if (!(state instanceof Examined examined)) {
            return state;
        }
        Look look = examined.look();
        ScanLanguages recorded = look.source() == Source.SCAN ? languages.get(look.id()) : null;
        return switch (scope) {
            case ToolScope.BuiltIn builtIn when builtIn.type() == FindingType.SAST
                    || builtIn.type() == FindingType.QUALITY -> semgrep(look, recorded);
            case ToolScope.Plugin ignored -> plugin(look, scoped, recorded);
            default -> state;
        };
    }

    private static ScopeState semgrep(Look look, ScanLanguages recorded) {
        if (recorded == null || recorded.detected().isEmpty()) {
            return new Missing(NoDataReason.LANGUAGES_UNRECORDED, Optional.of(look), Optional.of("scan " + look.id()
                    + " recorded no census of its tree: which languages it holds, and so whether its rules read"
                    + " any of them, is unknown"));
        }
        if (recorded.sastRules().isEmpty()) {
            return new Missing(NoDataReason.LANGUAGES_UNRECORDED, Optional.of(look), Optional.of("scan " + look.id()
                    + " did not record which languages its SAST rules read"));
        }
        Set<Language> detected = recorded.detected().get();
        Set<Language> source = SourceLanguages.of(detected);
        Set<Language> rules = recorded.sastRules().get();
        String read = "its SAST rules read " + names(rules);
        if (source.isEmpty()) {
            return new Missing(NoDataReason.LANGUAGE_NOT_ANALYSED, Optional.of(look), Optional.of("its tree holds no"
                    + " source language the census recognises (found: " + names(detected) + "); " + read
                    + " — nothing says its code was analysed"));
        }
        Set<Language> unread = source.stream().filter(language -> !rules.contains(language))
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(Language.class)));
        if (!unread.isEmpty()) {
            return new Missing(NoDataReason.LANGUAGE_NOT_ANALYSED, Optional.of(look), Optional.of("not analysed: "
                    + names(unread) + " — source languages in its tree: " + names(source) + "; " + read));
        }
        return new Examined(look, Optional.of("source languages analysed: " + names(source)));
    }

    private static ScopeState plugin(Look look, ScopeFacts scoped, ScanLanguages recorded) {
        if (recorded == null || recorded.detected().isEmpty()) {
            // An incomplete census runs every plugin (`LanguageCensus.Census.applies`): produced on a
            // tree nobody counted, it may have read none of it.
            return new Missing(NoDataReason.LANGUAGES_UNRECORDED, Optional.of(look), Optional.of("scan " + look.id()
                    + " recorded no census of its tree: a plugin runs on such a tree whatever its languages, and"
                    + " may have read nothing"));
        }
        Optional<Set<Language>> declared = scoped instanceof PluginRuns runs
                ? runs.withinAge().stream().filter(run -> run.scan().equals(look)).findFirst()
                        .flatMap(PluginRun::reads)
                : Optional.empty();
        if (declared.isEmpty()) {
            return new Missing(NoDataReason.LANGUAGES_UNRECORDED, Optional.of(look), Optional.of("the manifest"
                    + " scan " + look.id() + " ran the plugin with is no longer known: which languages it reads is"
                    + " unknown"));
        }
        Set<Language> detected = recorded.detected().get();
        Set<Language> reads = declared.get();
        if (detected.stream().noneMatch(reads::contains)) {
            return new Missing(NoDataReason.LANGUAGE_NOT_ANALYSED, Optional.of(look), Optional.of("it reads "
                    + names(reads) + ", and its tree holds none of them (found: " + names(detected) + ")"));
        }
        Set<Language> unread = SourceLanguages.of(detected).stream().filter(language -> !reads.contains(language))
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(Language.class)));
        return new Examined(look, Optional.of("it reads " + names(reads)
                + (unread.isEmpty() ? "" : "; source languages in its tree it does not read: " + names(unread))));
    }

    private static String names(Set<Language> languages) {
        return languages.isEmpty()
                ? "none"
                : languages.stream().map(Language::wireName).sorted().collect(Collectors.joining(", "));
    }

    // ------------------------------------------------------------------ the kinds

    private static Measurement findings(FindingsThreshold rule, MeasurementFacts facts, List<Long> repositories,
            Instant since) {
        Collector collector = new Collector();
        Map<Severity, long[]> totals = new EnumMap<>(Severity.class);
        List<Figure> figures = new ArrayList<>();
        for (ToolScope scope : rule.scopes()) {
            Set<Long> included = collector.scope(scope, facts, repositories, since);
            Map<Severity, long[]> counts = counts(facts.counts().get(scope.key()), included);
            counts.forEach((severity, pair) -> {
                figures.add(new Figure(scope.key(), severity.wireName(), pair[0], pair[1], Optional.empty(), Optional.empty()));
                long[] total = totals.computeIfAbsent(severity, key -> new long[2]);
                total[0] += pair[0];
                total[1] += pair[1];
            });
        }
        return judged(collector, rule.thresholds(), totals, figures, describe(rule.scopes()));
    }

    private static Measurement dependencies(DependencyAnalysis rule, MeasurementFacts facts, List<Long> repositories,
            Instant since) {
        String key = new ToolScope.BuiltIn(FindingType.VULNERABILITY).key();
        Collector collector = new Collector();
        Map<Long, ScopeFacts> scoped = facts.scopes().getOrDefault(key, Map.of());
        for (long repository : repositories) {
            ScopeState state = classify(scoped.get(repository), since);
            if (!(state instanceof Examined examined)) {
                collector.add(repository, Optional.empty(), state);
                continue;
            }
            List<String> unmet = new ArrayList<>();
            if (!(scoped.get(repository) instanceof Scanned scanned && scanned.sbomStored())) {
                unmet.add("its newest analysed scan stored no SBOM");
            }
            if (rule.requireSchedule() && !facts.scheduled().getOrDefault(repository, false)) {
                unmet.add("it is not scheduled at least every " + days(rule.maxAgeDays()));
            }
            collector.examined(repository, Optional.empty(), examined.look(), unmet);
        }
        Map<Severity, long[]> totals = counts(facts.counts().get(key), collector.included());
        List<Figure> figures = new ArrayList<>();
        totals.forEach((severity, pair) ->
                figures.add(new Figure(key, severity.wireName(), pair[0], pair[1], Optional.empty(), Optional.empty())));
        return judged(collector, rule.thresholds(), totals, figures, "dependency analysis");
    }

    private static Measurement coverage(CoverageThreshold rule, MeasurementFacts facts, List<Long> repositories,
            Instant since) {
        Collector collector = new Collector();
        long coveredSum = 0;
        long totalSum = 0;
        for (long repository : repositories) {
            CoverageReport report = facts.coverage().get(repository);
            if (report == null) {
                collector.add(repository, Optional.empty(), new Missing(NoDataReason.NEVER_EXAMINED, Optional.empty()));
                continue;
            }
            if (report.look().at().isBefore(since)) {
                collector.add(repository, Optional.empty(), new Missing(NoDataReason.STALE, Optional.of(report.look())));
                continue;
            }
            long covered;
            long total;
            if (rule.metric() == ChecklistRule.Metric.BRANCH) {
                if (report.branchesTotal().isEmpty() || report.branchesCovered().isEmpty()) {
                    // Counted no branch: not 0 of 0, and not a pass — it did not look.
                    collector.missing(repository, Optional.empty(), NoDataReason.STEP_ABSENT, Optional.of(report.look()),
                            "the report counted no branch");
                    continue;
                }
                covered = report.branchesCovered().get();
                total = report.branchesTotal().get();
            } else {
                covered = report.linesCovered();
                total = report.linesTotal();
            }
            if (total <= 0) {
                collector.missing(repository, Optional.empty(), NoDataReason.STEP_ABSENT, Optional.of(report.look()),
                        "the report counted nothing");
                continue;
            }
            coveredSum += covered;
            totalSum += total;
            String ratio = covered + " of " + total + " " + rule.metric().wireName() + "s covered";
            if (rule.aggregation() == ChecklistRule.Aggregation.PER_REPOSITORY) {
                collector.examined(repository, Optional.empty(), report.look(),
                        Ratios.atLeast(covered, total, rule.minimumRatio())
                                ? List.of()
                                : List.of(ratio + ", under " + percent(rule.minimumRatio())), ratio);
            } else {
                collector.examinedUnjudged(repository, report.look(), ratio);
            }
        }
        List<String> projectUnmet = new ArrayList<>();
        if (rule.aggregation() == ChecklistRule.Aggregation.PROJECT_WEIGHTED && collector.complete()
                && !Ratios.atLeast(coveredSum, totalSum, rule.minimumRatio())) {
            projectUnmet.add("the project's " + coveredSum + " of " + totalSum + " " + rule.metric().wireName()
                    + "s covered is under " + percent(rule.minimumRatio()));
        }
        return collector.outcome(projectUnmet, List.of(), rule.metric().wireName() + " coverage of at least "
                + percent(rule.minimumRatio()));
    }

    private static Measurement tests(TestSuitePassed rule, MeasurementFacts facts, List<Long> repositories, Instant since) {
        Collector collector = new Collector();
        SuitePattern pattern = SuitePattern.of(rule.suitePattern());
        for (long repository : repositories) {
            TestReport report = facts.tests().get(repository);
            if (report == null) {
                collector.add(repository, Optional.empty(), new Missing(NoDataReason.NEVER_EXAMINED, Optional.empty()));
                continue;
            }
            if (report.look().at().isBefore(since)) {
                collector.add(repository, Optional.empty(), new Missing(NoDataReason.STALE, Optional.of(report.look())));
                continue;
            }
            List<Suite> matched = report.suites().stream().filter(suite -> pattern.matches(suite.name())).toList();
            if (matched.isEmpty()) {
                collector.missing(repository, Optional.empty(), NoDataReason.SUITE_NOT_FOUND, Optional.of(report.look()),
                        "no suite matches " + rule.suitePattern());
                continue;
            }
            long ran = matched.stream().mapToLong(suite -> (long) suite.tests() - suite.skipped()).sum();
            if (ran <= 0) {
                collector.missing(repository, Optional.empty(), NoDataReason.NO_TEST_RAN, Optional.of(report.look()),
                        matched.size() + (matched.size() == 1 ? " suite matches" : " suites match") + " and ran no test");
                continue;
            }
            long failures = matched.stream().mapToLong(Suite::failures).sum();
            long errors = matched.stream().mapToLong(Suite::errors).sum();
            List<String> unmet = new ArrayList<>();
            if (failures > 0 || errors > 0) {
                unmet.add(failures + " failed and " + errors + " errored");
            }
            if (ran < rule.minimumTests()) {
                unmet.add(ran + " ran, fewer than " + rule.minimumTests());
            }
            collector.examined(repository, Optional.empty(), report.look(), unmet,
                    matched.size() + (matched.size() == 1 ? " suite" : " suites") + ", " + ran + " tests ran");
        }
        return collector.outcome(List.of(), List.of(), "suites matching " + rule.suitePattern() + " passed");
    }

    private static Measurement components(ComponentVersions rule, MeasurementFacts facts, List<Long> repositories,
            Instant since) {
        String key = new ToolScope.BuiltIn(FindingType.VULNERABILITY).key();
        Map<Long, ScopeFacts> scoped = facts.scopes().getOrDefault(key, Map.of());
        Collector collector = new Collector();
        for (long repository : repositories) {
            ScopeState state = classify(scoped.get(repository), since);
            if (!(state instanceof Examined examined)) {
                collector.add(repository, Optional.empty(), state);
                continue;
            }
            if (!(scoped.get(repository) instanceof Scanned scanned && scanned.sbomStored())) {
                collector.examined(repository, Optional.empty(), examined.look(),
                        List.of("its newest analysed scan stored no SBOM"));
                continue;
            }
            List<MeasurementFacts.Component> listed = facts.components().getOrDefault(repository, List.of());
            List<String> unmet = new ArrayList<>();
            List<String> found = new ArrayList<>();
            for (AllowedComponent allowed : rule.components()) {
                List<MeasurementFacts.Component> occurrences = listed.stream()
                        .filter(component -> allowed.names(component.purl())).toList();
                if (occurrences.isEmpty()) {
                    unmet.add(allowed.endsOnSeparator()
                            ? allowed.purlPrefix() + " ends on its separator and names no package — bind it without"
                                    + " the last character"
                            : allowed.purlPrefix() + " is not in its SBOM");
                    continue;
                }
                Set<String> versions = occurrences.stream()
                        .map(component -> component.version() == null ? "(no version)" : component.version())
                        .collect(Collectors.toCollection(java.util.TreeSet::new));
                found.add(allowed.purlPrefix() + " at " + String.join(", ", versions));
                Set<String> refused = versions.stream().filter(version -> !allowed.versions().contains(version))
                        .collect(Collectors.toCollection(java.util.TreeSet::new));
                if (!refused.isEmpty()) {
                    unmet.add(allowed.purlPrefix() + " at " + String.join(", ", refused) + ", not an allowed version");
                }
            }
            collector.examined(repository, Optional.empty(), examined.look(), unmet, String.join("; ", found));
        }
        return collector.outcome(List.of(), List.of(), rule.components().size()
                + (rule.components().size() == 1 ? " declared package" : " declared packages") + " at allowed versions");
    }

    // ------------------------------------------------------------------ thresholds

    /** Complete data judged against the thresholds; incomplete data reported, unjudged. */
    private static Measurement judged(Collector collector, Map<Severity, SeverityThreshold> thresholds,
            Map<Severity, long[]> totals, List<Figure> figures, String what) {
        List<String> unmet = new ArrayList<>();
        List<Figure> judged = new ArrayList<>(figures);
        thresholds.forEach((severity, threshold) -> {
            long[] pair = totals.getOrDefault(severity, new long[2]);
            long open = pair[0];
            long resolved = pair[1];
            List<String> failures = new ArrayList<>();
            threshold.maxOpen().filter(max -> open > max)
                    .ifPresent(max -> failures.add(open + " open, more than " + max));
            // Resolved ÷ (resolved + open): with no issue of the severity, nothing is left to resolve —
            // the scopes looked (the data is complete) and found none, which meets the ratio.
            threshold.minResolvedRatio().filter(min -> !Ratios.atLeast(resolved, resolved + open, min))
                    .ifPresent(min -> failures.add(resolved + " of " + (resolved + open) + " resolved, under "
                            + percent(min)));
            boolean complete = collector.complete();
            judged.add(new Figure(Figure.ALL_SCOPES, severity.wireName(), open, resolved,
                    complete ? Optional.of(failures.isEmpty()) : Optional.empty(),
                    failures.isEmpty() ? Optional.empty() : Optional.of(String.join("; ", failures))));
            if (complete) {
                failures.forEach(failure -> unmet.add(severity.wireName() + ": " + failure));
            }
        });
        return collector.outcome(unmet, judged, what);
    }

    /** Open and resolved per severity over the repositories included; a state this version does not know is open. */
    private static Map<Severity, long[]> counts(Map<Long, List<IssueCount>> byRepository, Set<Long> included) {
        Map<Severity, long[]> counts = new EnumMap<>(Severity.class);
        if (byRepository == null) {
            return counts;
        }
        for (long repository : included) {
            for (IssueCount count : byRepository.getOrDefault(repository, List.of())) {
                long[] pair = counts.computeIfAbsent(Severity.of(count.severity()), key -> new long[2]);
                if (IssueState.RESOLVED.wireName().equals(count.state())) {
                    pair[1] += count.count();
                } else {
                    pair[0] += count.count();
                }
            }
        }
        return counts;
    }

    // ------------------------------------------------------------------ gathering the evidence

    /** The evidence of one measurement as it is read, repository by repository, and what it adds up to. */
    private static final class Collector {

        private final List<RepositoryEvidence> evidence = new ArrayList<>();
        private final List<NoDataReason> missing = new ArrayList<>();
        private final List<String> unmet = new ArrayList<>();
        private final Set<Long> included = new LinkedHashSet<>();
        private final List<Instant> looks = new ArrayList<>();

        /**
         * One scope over every repository; answers the repositories where it looked. A scope not
         * applicable on every repository is no data of its own: it looked at nothing.
         */
        Set<Long> scope(ToolScope scope, MeasurementFacts facts, List<Long> repositories, Instant since) {
            Map<Long, ScopeFacts> scoped = facts.scopes().getOrDefault(scope.key(), Map.of());
            Optional<String> named = Optional.of(scope.key());
            Set<Long> examined = new LinkedHashSet<>();
            boolean everywhereNotApplicable = true;
            for (long repository : repositories) {
                ScopeFacts about = scoped.get(repository);
                ScopeState state = read(scope, about, classify(about, since), facts.languages());
                add(repository, named, state);
                if (state instanceof Examined) {
                    examined.add(repository);
                }
                everywhereNotApplicable &= state instanceof NotApplicable;
            }
            if (everywhereNotApplicable) {
                missing.add(NoDataReason.NOT_APPLICABLE_ANYWHERE);
            }
            return examined;
        }

        void add(long repository, Optional<String> scope, ScopeState state) {
            switch (state) {
                case Examined examined -> {
                    evidence.add(new RepositoryEvidence(repository, scope, RepositoryEvidence.EXAMINED,
                            Optional.of(examined.look()), Optional.empty(), examined.note()));
                    included.add(repository);
                    looks.add(examined.look().at());
                }
                case NotApplicable skipped -> evidence.add(new RepositoryEvidence(repository, scope,
                        RepositoryEvidence.NOT_APPLICABLE, Optional.of(skipped.look()), Optional.empty(),
                        Optional.of("the plugin applies to none of its languages; left out of the figures")));
                case Missing absent -> missing(repository, scope, absent.reason(), absent.newest(),
                        absent.detail().orElse(null));
            }
        }

        void missing(long repository, Optional<String> scope, NoDataReason reason, Optional<Look> newest, String detail) {
            evidence.add(new RepositoryEvidence(repository, scope, reason.wireName(), newest, Optional.empty(),
                    Optional.ofNullable(detail)));
            missing.add(reason);
        }

        void examined(long repository, Optional<String> scope, Look look, List<String> failures) {
            examined(repository, scope, look, failures, null);
        }

        void examined(long repository, Optional<String> scope, Look look, List<String> failures, String detail) {
            List<String> details = new ArrayList<>();
            if (detail != null && !detail.isBlank()) {
                details.add(detail);
            }
            details.addAll(failures);
            evidence.add(new RepositoryEvidence(repository, scope, RepositoryEvidence.EXAMINED, Optional.of(look),
                    Optional.of(failures.isEmpty()), details.isEmpty() ? Optional.empty() : Optional.of(String.join("; ", details))));
            included.add(repository);
            looks.add(look.at());
            failures.forEach(failure -> unmet.add("repository " + repository + ": " + failure));
        }

        /** Read, and judged over the project rather than here. */
        void examinedUnjudged(long repository, Look look, String detail) {
            evidence.add(new RepositoryEvidence(repository, Optional.empty(), RepositoryEvidence.EXAMINED,
                    Optional.of(look), Optional.empty(), Optional.of(detail)));
            included.add(repository);
            looks.add(look.at());
        }

        /**
         * Where a headline's words alone do not say what to do — which languages nobody read, which
         * record is missing — the first repository's own sentence, so the line's summary names them.
         */
        private String firstReason(NoDataReason headline) {
            if (headline != NoDataReason.LANGUAGE_NOT_ANALYSED && headline != NoDataReason.LANGUAGES_UNRECORDED) {
                return "";
            }
            return evidence.stream()
                    .filter(line -> line.status().equals(headline.wireName()) && line.detail().isPresent())
                    .findFirst()
                    .map(line -> "; repository " + line.repositoryId() + ", " + line.detail().get())
                    .orElse("");
        }

        Set<Long> included() {
            return included;
        }

        boolean complete() {
            return missing.isEmpty();
        }

        Measurement outcome(List<String> projectUnmet, List<Figure> figures, String what) {
            Optional<Instant> asOf = looks.stream().min(Comparator.naturalOrder());
            if (!missing.isEmpty()) {
                NoDataReason headline = missing.stream().min(Comparator.naturalOrder()).orElseThrow();
                long lacking = evidence.stream()
                        .filter(line -> !line.status().equals(RepositoryEvidence.EXAMINED)
                                && !line.status().equals(RepositoryEvidence.NOT_APPLICABLE))
                        .map(RepositoryEvidence::repositoryId).distinct().count();
                String summary = headline == NoDataReason.NOT_APPLICABLE_ANYWHERE && lacking == 0
                        ? "No data (not_applicable_anywhere): the plugin applies to no repository of the project."
                        : "No data (" + headline.wireName() + ") for " + what + ": " + lacking + " of "
                                + evidence.stream().map(RepositoryEvidence::repositoryId).distinct().count()
                                + " repositories without evidence" + firstReason(headline) + ".";
                return new Measurement(MeasurementOutcome.NO_DATA, Optional.of(headline), asOf, evidence, figures, summary);
            }
            List<String> failures = new ArrayList<>(unmet);
            failures.addAll(projectUnmet);
            if (!failures.isEmpty()) {
                return new Measurement(MeasurementOutcome.FAIL, Optional.empty(), asOf, evidence, figures,
                        "Fail, " + what + ": " + String.join("; ", failures.subList(0, Math.min(failures.size(), 10)))
                                + (failures.size() > 10 ? "; and " + (failures.size() - 10) + " more." : "."));
            }
            return new Measurement(MeasurementOutcome.PASS, Optional.empty(), asOf, evidence, figures,
                    "Pass, " + what + ", on " + included.size() + (included.size() == 1 ? " repository" : " repositories")
                            + asOf.map(at -> ", as of " + at).orElse("") + ".");
        }
    }

    private static String describe(List<ToolScope> scopes) {
        return scopes.stream().map(ToolScope::key).collect(Collectors.joining(", "));
    }

    private static String days(int days) {
        return days + (days == 1 ? " day" : " days");
    }

    private static String percent(BigDecimal ratio) {
        return ratio.movePointRight(2).stripTrailingZeros().toPlainString() + " %";
    }
}

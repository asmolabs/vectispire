package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule;
import com.asmolabs.vectispire.common.domain.checklists.Measurement;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.IssueCount;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginState;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ScopeFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Source;
import com.asmolabs.vectispire.common.domain.checklists.RuleEvaluation;
import com.asmolabs.vectispire.common.domain.checklists.ToolScope;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.inventory.ComponentCatalog;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.plugins.CoverageImportView;
import com.asmolabs.vectispire.core.plugins.LatestTestReport;
import com.asmolabs.vectispire.core.plugins.PluginService;
import com.asmolabs.vectispire.core.plugins.ReportImportCatalog;
import com.asmolabs.vectispire.core.plugins.SarifImportView;
import com.asmolabs.vectispire.core.scanning.PluginOutcome;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.queries.ExaminingScanRow;
import com.asmolabs.vectispire.core.targets.CronExpressions;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * What a line's rule finds on a project now: the owners asked what they recorded, through their own
 * catalogues, and {@link RuleEvaluation} applying the rule (decision 0032 §6).
 *
 * <p><b>Each owner answers its own question.</b> The scans say in which scan a step produced and how
 * many scans within the age recorded their steps ({@code scanning}); the scans' own plugin steps say
 * each plugin's state ({@code scanning}); the imports say which accepted a tool, and the newest coverage
 * and test report ({@code plugins}); the backlog counts by scope, settled triage left out ({@code
 * issues}); the inventory lists an SBOM's components ({@code inventory}); the repositories carry their
 * schedules ({@code targets}); the static analysis and the plugins are judged by the languages the scan
 * they produced in recorded — its census, its rules' languages ({@code scanning}), the manifest it named
 * ({@code plugins}). No other module's repository is read, and no statement names another
 * module's entity: every question is a method of its owner's API.
 *
 * <p><b>Batched by the owners.</b> A project's repositories reach every one of those questions a
 * thousand at a time, the owner's own batching, and here too where the lookup is a plain one ({@link
 * TargetCatalog#repositories} is {@code findAllById}, one bind parameter per identifier).
 *
 * <p>Nothing here opens a transaction or writes: a measurement is stored by whoever relies on it.
 */
@Component
class ChecklistMeasurer {

    /** What one bound line's rule found. */
    record LineMeasurement(ChecklistItemEntity item, ChecklistRule rule, Measurement measurement) {}

    private static final int LOOKUP_BATCH = 1_000;

    private final ScanCatalog scans;
    private final IssueCatalog issues;
    private final ReportImportCatalog imports;
    private final ComponentCatalog components;
    private final TargetCatalog targets;
    private final PluginService plugins;

    ChecklistMeasurer(ScanCatalog scans, IssueCatalog issues, ReportImportCatalog imports, ComponentCatalog components,
            TargetCatalog targets, PluginService plugins) {
        this.scans = scans;
        this.issues = issues;
        this.imports = imports;
        this.components = components;
        this.targets = targets;
        this.plugins = plugins;
    }

    /** Every bound line of {@code items}, measured over these repositories at {@code now}, in their order. */
    List<LineMeasurement> measure(List<Long> repositoryIds, List<ChecklistItemEntity> items, Instant now) {
        List<LineMeasurement> measured = new ArrayList<>();
        for (ChecklistItemEntity item : items) {
            if (item.getBoundRule() != null) {
                measured.add(measure(repositoryIds, item, now));
            }
        }
        return measured;
    }

    LineMeasurement measure(List<Long> repositoryIds, ChecklistItemEntity item, Instant now) {
        ChecklistRule rule = ChecklistRule.fromCanonical(item.getBoundRule());
        return new LineMeasurement(item, rule, RuleEvaluation.evaluate(rule, facts(rule, repositoryIds, now), now));
    }

    // ------------------------------------------------------------------ asking the owners

    private MeasurementFacts facts(ChecklistRule rule, List<Long> repositoryIds, Instant now) {
        List<Long> repositories = repositoryIds.stream().distinct().sorted().toList();
        Instant since = now.minus(rule.maxAge());
        Map<String, Map<Long, ScopeFacts>> scopes = new HashMap<>();
        Map<String, Map<Long, List<IssueCount>>> counts = new HashMap<>();
        Map<Long, Boolean> scheduled = Map.of();
        Map<Long, MeasurementFacts.CoverageReport> coverage = Map.of();
        Map<Long, MeasurementFacts.TestReport> tests = Map.of();
        Map<Long, List<MeasurementFacts.Component>> listed = Map.of();
        Set<Long> languageScans = new java.util.HashSet<>();
        if (repositories.isEmpty()) {
            return new MeasurementFacts(repositories, scopes, counts, scheduled, coverage, tests, listed);
        }
        switch (rule) {
            case ChecklistRule.DependencyAnalysis dependency -> {
                ToolScope.BuiltIn scope = new ToolScope.BuiltIn(FindingType.VULNERABILITY);
                scopes.put(scope.key(), scanned(repositories, FindingType.VULNERABILITY, since).facts());
                counts.put(scope.key(), counts(issues.countUnsettledOfTypeWithin(FindingType.VULNERABILITY.wireName(),
                        repositories)));
                if (dependency.requireSchedule()) {
                    scheduled = scheduled(repositories, rule.maxAge(), now);
                }
            }
            case ChecklistRule.FindingsThreshold findings -> {
                for (ToolScope scope : findings.scopes()) {
                    switch (scope) {
                        case ToolScope.BuiltIn builtIn -> {
                            Scanned scanned = scanned(repositories, builtIn.type(), since);
                            scopes.put(scope.key(), scanned.facts());
                            if (builtIn.type() == FindingType.SAST || builtIn.type() == FindingType.QUALITY) {
                                scanned.newest().values().forEach(row -> languageScans.add(row.scanId()));
                            }
                            counts.put(scope.key(), counts(issues.countUnsettledOfTypeWithin(builtIn.type().wireName(),
                                    repositories)));
                        }
                        case ToolScope.Plugin plugin -> {
                            Map<Long, ScopeFacts> runs = plugin(repositories, plugin.pluginId(), since);
                            scopes.put(scope.key(), runs);
                            runs.values().forEach(facts -> ((MeasurementFacts.PluginRuns) facts).withinAge()
                                    .forEach(run -> languageScans.add(run.scan().id())));
                            counts.put(scope.key(), counts(issues.countUnsettledOfToolWithin(scope.key(), repositories)));
                        }
                        case ToolScope.Imported imported -> {
                            scopes.put(scope.key(), imported(repositories, imported, since));
                            counts.put(scope.key(), counts(issues.countUnsettledOfToolWithin(scope.key(), repositories)));
                        }
                    }
                }
            }
            case ChecklistRule.CoverageThreshold ignored -> coverage = coverage(repositories);
            case ChecklistRule.TestSuitePassed ignored -> tests = tests(repositories);
            case ChecklistRule.ComponentVersions ignored -> {
                ToolScope.BuiltIn scope = new ToolScope.BuiltIn(FindingType.VULNERABILITY);
                Scanned scanned = scanned(repositories, FindingType.VULNERABILITY, since);
                scopes.put(scope.key(), scanned.facts());
                listed = components(scanned.newest());
            }
        }
        return new MeasurementFacts(repositories, scopes, counts, scheduled, coverage, tests, listed,
                languages(languageScans));
    }

    /** What the scans a language-scoped analysis produced in recorded of languages, by scan id. */
    private Map<Long, MeasurementFacts.ScanLanguages> languages(Set<Long> scanIds) {
        if (scanIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, MeasurementFacts.ScanLanguages> languages = new HashMap<>();
        scans.languagesOf(scanIds).forEach((scanId, recorded) ->
                languages.put(scanId, new MeasurementFacts.ScanLanguages(recorded.detected(), recorded.sastRules())));
        return languages;
    }

    /** A built-in step's facts per repository, and the newest scans in which it produced, at any age. */
    private record Scanned(Map<Long, ScopeFacts> facts, Map<Long, ExaminingScanRow> newest) {}

    private Scanned scanned(List<Long> repositories, FindingType type, Instant since) {
        // At any age: whether the newest look is within the age, stale or absent is the rule's to say.
        Map<Long, ExaminingScanRow> newest = scans.newestExamining(repositories, type, Instant.EPOCH);
        Map<Long, ScanCatalog.ScansWithin> within = scans.completedWithin(repositories, since);
        Map<Long, ScopeFacts> facts = new HashMap<>();
        for (long repository : repositories) {
            Optional<ExaminingScanRow> row = Optional.ofNullable(newest.get(repository));
            ScanCatalog.ScansWithin counted = within.get(repository);
            long unrecorded = counted == null ? 0 : counted.unrecorded();
            long recorded = counted == null ? 0 : counted.completed() - unrecorded;
            facts.put(repository, new MeasurementFacts.Scanned(
                    row.map(scan -> new Look(Source.SCAN, scan.scanId(), scan.createdAt(), Optional.empty())),
                    row.map(ExaminingScanRow::sbomStored).orElse(false), (int) recorded, (int) unrecorded));
        }
        return new Scanned(facts, newest);
    }

    private Map<Long, ScopeFacts> plugin(List<Long> repositories, String pluginId, Instant since) {
        Map<Long, List<ScanCatalog.PluginRun>> runs = scans.pluginRunsWithin(repositories, pluginId, since);
        Map<Long, ScanCatalog.ScansWithin> within = scans.completedWithin(repositories, since);
        Set<Long> namedBefore = scans.namingPluginBefore(repositories, pluginId, since);
        Map<Long, ScopeFacts> facts = new HashMap<>();
        // By the digest each scan named, never the plugin's current manifest: an update that added a
        // language would otherwise claim it for scans that ran without it. Manifests are kept forever
        // (`PluginService.manifest`), and a project's scans name few of them.
        Map<String, Optional<Set<Language>>> declared = new HashMap<>();
        for (long repository : repositories) {
            List<MeasurementFacts.PluginRun> states = runs.getOrDefault(repository, List.of()).stream()
                    .map(run -> new MeasurementFacts.PluginRun(
                            new Look(Source.SCAN, run.scanId(), run.createdAt(), Optional.empty()), state(run.outcome()),
                            run.outcome().manifestDigest() == null
                                    ? Optional.empty()
                                    : declared.computeIfAbsent(run.outcome().manifestDigest(), digest -> plugins
                                            .manifest(new PluginRef(pluginId, digest)).map(PluginManifest::languages))))
                    .toList();
            ScanCatalog.ScansWithin counted = within.get(repository);
            facts.put(repository, new MeasurementFacts.PluginRuns(states, counted == null ? 0 : (int) counted.completed(),
                    namedBefore.contains(repository)));
        }
        return facts;
    }

    /**
     * A plugin's stored state, decision 0017's three and the refusal by its reason. One this version
     * does not know did not produce: read as absent — should have run, did not — never as produced nor
     * as not applicable; so is a refusal whose reason it does not know.
     */
    private static PluginState state(PluginOutcome outcome) {
        return PluginOutcome.State.fromWire(outcome.state()).map(state -> switch (state) {
            case PRODUCED -> PluginState.PRODUCED;
            case NOT_APPLICABLE -> PluginState.NOT_APPLICABLE;
            case ABSENT -> PluginState.ABSENT;
            case REFUSED -> {
                PluginStep.Refusal refusal = PluginStep.Refusal.fromWire(outcome.refusal());
                yield refusal == null ? PluginState.ABSENT : switch (refusal) {
                    case UNSIGNED -> PluginState.REFUSED_UNSIGNED;
                    case SIGNATURE_UNVERIFIED -> PluginState.REFUSED_SIGNATURE_UNVERIFIED;
                    case REGISTRY_AUTHENTICATION_REQUIRED -> PluginState.REFUSED_REGISTRY_AUTHENTICATION_REQUIRED;
                };
            }
        }).orElse(PluginState.ABSENT);
    }

    private Map<Long, ScopeFacts> imported(List<Long> repositories, ToolScope.Imported scope, Instant since) {
        Map<Long, SarifImportView> newest = imports.newestCarrying(repositories, scope.key());
        Set<Long> unrecorded = imports.unrecordedSince(repositories, scope.sourceSlug(), since);
        Map<Long, ScopeFacts> facts = new HashMap<>();
        for (long repository : repositories) {
            Optional<SarifImportView> row = Optional.ofNullable(newest.get(repository));
            facts.put(repository, new MeasurementFacts.Imported(
                    row.map(sarif -> new Look(Source.SARIF_IMPORT, sarif.id(), sarif.importedAt(),
                            Optional.ofNullable(sarif.documentSha256()))),
                    unrecorded.contains(repository)));
        }
        return facts;
    }

    private static Map<Long, List<IssueCount>> counts(List<IssueCatalog.ScopeCount> rows) {
        Map<Long, List<IssueCount>> byRepository = new HashMap<>();
        for (IssueCatalog.ScopeCount row : rows) {
            byRepository.computeIfAbsent(row.repositoryId(), id -> new ArrayList<>())
                    .add(new IssueCount(row.severity(), row.state(), row.count()));
        }
        Map<Long, List<IssueCount>> answer = new HashMap<>();
        byRepository.forEach((repository, list) -> answer.put(repository, List.copyOf(list)));
        return answer;
    }

    /** Whether each repository's schedule runs it at least once per maximum age — the cron first, as the scheduler reads it. */
    private Map<Long, Boolean> scheduled(List<Long> repositories, Duration maxAge, Instant now) {
        Map<Long, Boolean> scheduled = new HashMap<>();
        for (int from = 0; from < repositories.size(); from += LOOKUP_BATCH) {
            for (RepositoryView repository : targets.repositories(
                    repositories.subList(from, Math.min(from + LOOKUP_BATCH, repositories.size())))) {
                Duration interval = repository.scanIntervalMinutes() == null
                        ? Duration.ZERO
                        : Duration.ofMinutes(repository.scanIntervalMinutes());
                scheduled.put(repository.id(), Schedules.runsAtLeastEvery(CronExpressions.parse(repository.scanCron()),
                        interval, maxAge, now));
            }
        }
        return scheduled;
    }

    private Map<Long, MeasurementFacts.CoverageReport> coverage(List<Long> repositories) {
        Map<Long, MeasurementFacts.CoverageReport> reports = new HashMap<>();
        for (Map.Entry<Long, CoverageImportView> entry : imports.newestCoverage(repositories).entrySet()) {
            CoverageImportView row = entry.getValue();
            reports.put(entry.getKey(), new MeasurementFacts.CoverageReport(
                    new Look(Source.COVERAGE_IMPORT, row.id(), row.importedAt(), Optional.ofNullable(row.documentSha256())),
                    row.linesCovered(), row.linesTotal(), Optional.ofNullable(row.branchesCovered()),
                    Optional.ofNullable(row.branchesTotal())));
        }
        return reports;
    }

    private Map<Long, MeasurementFacts.TestReport> tests(List<Long> repositories) {
        Map<Long, MeasurementFacts.TestReport> reports = new HashMap<>();
        for (Map.Entry<Long, LatestTestReport> entry : imports.newestTestReports(repositories).entrySet()) {
            LatestTestReport latest = entry.getValue();
            reports.put(entry.getKey(), new MeasurementFacts.TestReport(
                    new Look(Source.TEST_REPORT_IMPORT, latest.report().id(), latest.report().importedAt(),
                            Optional.ofNullable(latest.report().documentSha256())),
                    latest.suites().stream().map(suite -> new MeasurementFacts.Suite(suite.name(), suite.testsCount(),
                            suite.failuresCount(), suite.errorsCount(), suite.skippedCount())).toList()));
        }
        return reports;
    }

    /** The components of each repository's newest analysed scan; an empty list where the inventory holds none. */
    private Map<Long, List<MeasurementFacts.Component>> components(Map<Long, ExaminingScanRow> newest) {
        Map<Long, List<ComponentCatalog.Component>> byScan = components.componentsOf(
                newest.values().stream().map(ExaminingScanRow::scanId).toList());
        Map<Long, List<MeasurementFacts.Component>> listed = new HashMap<>();
        newest.forEach((repository, scan) -> listed.put(repository, byScan.getOrDefault(scan.scanId(), List.of()).stream()
                .map(component -> new MeasurementFacts.Component(component.name(), component.version(), component.purl()))
                .toList()));
        return listed;
    }
}

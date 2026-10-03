package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * What the owners of the evidence answered about a project's repositories — the scans, the plugins'
 * outcomes, the imports, the backlog, the SBOMs — as the rules read it (decision 0032 §6). The
 * control plane asks the owners' catalogues and hands this over; {@link RuleEvaluation} decides, with
 * no database and no clock of its own.
 *
 * <p><b>Facts, not verdicts.</b> Whether a step is stale, absent or unrecorded is a rule, and rules
 * are here; what the owners report is what they recorded — the newest scan in which a step produced,
 * how many scans within the age recorded their steps and how many predate the record, each plugin's
 * state per scan. A repository missing from a map is one the owner knows nothing of for that question,
 * which the rules read as "never examined", never as "examined, and clean".
 *
 * @param repositoryIds the project's repositories, as the whole-project guard saw them
 * @param scopes for each scope's key, each repository's facts about it
 * @param counts for each scope's key, each repository's issues by severity and state, settled triage
 *     already left out by the owner's query
 * @param scheduled for the dependency rule that asks it, whether each repository's schedule runs at
 *     least as often as the rule's maximum age
 * @param coverage each repository's newest coverage import, at any age
 * @param tests each repository's newest test report, at any age
 * @param components the components of each repository's newest scan in which the dependency step
 *     produced, at any age — the scan {@code scopes} names for {@code builtin:vulnerability}
 * @param languages by scan id, what the scans a language-scoped analysis produced in recorded of
 *     languages — the static analysis steps and the plugins; a scan missing here recorded nothing
 */
public record MeasurementFacts(
        List<Long> repositoryIds,
        Map<String, Map<Long, ScopeFacts>> scopes,
        Map<String, Map<Long, List<IssueCount>>> counts,
        Map<Long, Boolean> scheduled,
        Map<Long, CoverageReport> coverage,
        Map<Long, TestReport> tests,
        Map<Long, List<Component>> components,
        Map<Long, ScanLanguages> languages) {

    /** Facts for rules that read no language — every one but the static analysis and the plugins. */
    public MeasurementFacts(List<Long> repositoryIds, Map<String, Map<Long, ScopeFacts>> scopes,
            Map<String, Map<Long, List<IssueCount>>> counts, Map<Long, Boolean> scheduled,
            Map<Long, CoverageReport> coverage, Map<Long, TestReport> tests, Map<Long, List<Component>> components) {
        this(repositoryIds, scopes, counts, scheduled, coverage, tests, components, Map.of());
    }

    public MeasurementFacts {
        repositoryIds = List.copyOf(repositoryIds);
        scopes = Map.copyOf(scopes);
        counts = Map.copyOf(counts);
        scheduled = Map.copyOf(scheduled);
        coverage = Map.copyOf(coverage);
        tests = Map.copyOf(tests);
        components = Map.copyOf(components);
        languages = Map.copyOf(languages);
    }

    /** Where a piece of evidence was read. */
    public enum Source {
        SCAN,
        SARIF_IMPORT,
        COVERAGE_IMPORT,
        TEST_REPORT_IMPORT;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * One scan or import a measurement rests on: what it was, when, and the digest of the document an
     * import accepted — which lets an auditor match the line with the report a pipeline sent.
     */
    public record Look(Source source, long id, Instant at, Optional<String> digest) {

        public Look {
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(at, "at");
            Objects.requireNonNull(digest, "digest");
        }
    }

    /** What an owner recorded about one scope on one repository. */
    public sealed interface ScopeFacts permits Scanned, PluginRuns, Imported {}

    /**
     * A built-in step, as the scans recorded it.
     *
     * @param newestProducing the repository's newest completed scan, at any age, in which the step
     *     produced — recorded in {@code examined_types}
     * @param sbomStored whether that scan stored an SBOM
     * @param recordedWithinAge completed scans within the age that recorded which steps produced
     * @param unrecordedWithinAge completed scans within the age from before the record existed
     */
    public record Scanned(Optional<Look> newestProducing, boolean sbomStored, int recordedWithinAge,
            int unrecordedWithinAge) implements ScopeFacts {

        public Scanned {
            Objects.requireNonNull(newestProducing, "newestProducing");
        }
    }

    /**
     * A plugin's state in one scan: decision 0017's three, kept apart, and the executor's refusal by its
     * reason — the reason is what the line's measurement names.
     */
    public enum PluginState {
        PRODUCED,
        NOT_APPLICABLE,
        ABSENT,
        /** Not started: no signer declared where one is required, and no waiver. */
        REFUSED_UNSIGNED,
        /** Not started: the declared signer did not verify the image. */
        REFUSED_SIGNATURE_UNVERIFIED,
        /** Not started: the registry would not let its signature be read, so nobody knows who signed it. */
        REFUSED_REGISTRY_AUTHENTICATION_REQUIRED
    }

    /**
     * @param reads the languages the plugin's manifest declared in that scan — the manifest the scan
     *     named by its digest, never the plugin's current one; empty when that manifest is not known
     */
    public record PluginRun(Look scan, PluginState state, Optional<Set<Language>> reads) {

        public PluginRun {
            Objects.requireNonNull(scan, "scan");
            Objects.requireNonNull(state, "state");
            reads = reads.map(Set::copyOf);
        }

        public PluginRun(Look scan, PluginState state) {
            this(scan, state, Optional.empty());
        }
    }

    /**
     * A plugin, as the scans recorded it.
     *
     * @param withinAge its state in each completed scan within the age that names it, newest first
     * @param scansWithinAge every completed scan within the age, naming it or not: one that does not
     *     name it ran without it, which is absent
     * @param namedBefore whether a completed scan older than the age names it
     */
    public record PluginRuns(List<PluginRun> withinAge, int scansWithinAge, boolean namedBefore) implements ScopeFacts {

        public PluginRuns {
            withinAge = List.copyOf(withinAge);
        }
    }

    /**
     * An imported tool, as its declared source's imports recorded it.
     *
     * @param newestProducing the newest import, at any age, whose accepted runs include the tool
     * @param unrecordedWithinAge whether an import from the source within the age predates the record
     *     of which tools an import carried — it may have carried this one
     */
    public record Imported(Optional<Look> newestProducing, boolean unrecordedWithinAge) implements ScopeFacts {

        public Imported {
            Objects.requireNonNull(newestProducing, "newestProducing");
        }
    }

    /**
     * What one scan recorded of languages. Each is empty where it recorded none, which is unknown —
     * never the empty set, which is "counted, and none".
     *
     * @param detected the languages its census found in the tree ({@code detected_languages})
     * @param sastRules the languages the Semgrep rules of its task read ({@code sast_languages})
     */
    public record ScanLanguages(Optional<Set<Language>> detected, Optional<Set<Language>> sastRules) {

        public ScanLanguages {
            detected = detected.map(Set::copyOf);
            sastRules = sastRules.map(Set::copyOf);
        }
    }

    /** Issues of one severity in one state, on one repository and one scope. */
    public record IssueCount(String severity, String state, long count) {}

    /**
     * @param branchesCovered and {@code branchesTotal}: empty when the report counted no branch
     */
    public record CoverageReport(Look look, long linesCovered, long linesTotal, Optional<Long> branchesCovered,
            Optional<Long> branchesTotal) {}

    public record TestReport(Look look, List<Suite> suites) {

        public TestReport {
            suites = List.copyOf(suites);
        }
    }

    public record Suite(String name, int tests, int failures, int errors, int skipped) {}

    /** A component as the SBOM listed it; the version is the one the inventory stored. */
    public record Component(String name, String version, String purl) {

        /**
         * The literal Syft writes where it could not tell a package's version — a Maven dependency
         * whose version is inherited from a parent or a BOM it does not resolve, or a property it
         * cannot expand. Checked on the pinned image: such a dependency comes out as
         * {@code "version": "UNKNOWN"} with a purl that carries no version at all.
         */
        private static final String SYFT_UNKNOWN = "UNKNOWN";

        /**
         * The version the SBOM states, or absent where it states none — no version, a blank one, or
         * Syft's {@code UNKNOWN}. Absent is not a version (decision 0007): read as one, a package
         * present in the tree was judged "not an allowed version" and the automatic answer wrote
         * "no" for a module that is there.
         */
        public Optional<String> statedVersion() {
            if (version == null || version.isBlank() || version.strip().equalsIgnoreCase(SYFT_UNKNOWN)) {
                return Optional.empty();
            }
            return Optional.of(version);
        }
    }
}

package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * What a checklist line is measured by: a closed set of kinds, each with the parameters a person
 * binds on a draft version (decision 0032 §6).
 *
 * <p><b>Parameters, never a sentence.</b> A threshold is the organisation's KPI, stated when the rule
 * is bound, beside the KPI's text; a number read out of the text would be a rule nobody wrote. And no
 * parameter has a product default that decides an outcome: the maximum age is required of every kind
 * (the form proposes seven days), whether the schedule must match is stated, a findings rule names its
 * thresholds. What is not stated is refused, never assumed.
 *
 * <p><b>The canonical form is a data contract.</b> {@link #canonical()} is stored as the item's bound
 * rule and enters its content digest (§4): a line whose binding moved is <em>changed</em>, and an
 * answer carried onto it waits for a person's confirmation. Keys sorted, no whitespace, ratios in
 * their one decimal form, lists in a fixed order — so the same rule is the same bytes. A change of
 * this writing is a change of every bound item's digest, which marks every such line changed in the
 * next version; add a key only when present, as the plugin manifest does.
 */
public sealed interface ChecklistRule {

    /** A year and a day: evidence older than that is no measurement of the state a release ships in. */
    int MAX_AGE_DAYS = 366;

    int MAX_SCOPES = 20;
    int MAX_COMPONENTS = 50;
    int MAX_PATTERN = 500;
    int MAX_TESTS = 10_000_000;

    Kind kind();

    /** How old the evidence may be — required of every kind. */
    int maxAgeDays();

    default Duration maxAge() {
        return Duration.ofDays(maxAgeDays());
    }

    /** The kinds, as the API and the stored form name them. */
    enum Kind {
        DEPENDENCY_ANALYSIS,
        FINDINGS_THRESHOLD,
        COVERAGE_THRESHOLD,
        TEST_SUITE_PASSED,
        COMPONENT_VERSIONS;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }

        static Kind parse(String value) {
            String wanted = value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
            return Arrays.stream(values()).filter(kind -> kind.wireName().equals(wanted)).findFirst()
                    .orElseThrow(() -> new InvalidInputException("A rule's kind is one of "
                            + Arrays.stream(values()).map(Kind::wireName).collect(Collectors.joining(", "))
                            + (wanted.isEmpty() ? "; none was given." : "; \"" + BoundedText.clip(wanted, 40)
                                    + "\" is not one.")));
        }
    }

    /**
     * The repository's dependencies analysed: its newest scan whose dependency step produced is within
     * the age and stored an SBOM, the repository is — if asked — scheduled at least as often as the
     * maximum age, and the open vulnerabilities meet the thresholds, if any are stated.
     */
    record DependencyAnalysis(int maxAgeDays, boolean requireSchedule, Map<Severity, SeverityThreshold> thresholds)
            implements ChecklistRule {

        public DependencyAnalysis {
            requireAge(maxAgeDays);
            thresholds = orderedThresholds(thresholds);
        }

        @Override
        public Kind kind() {
            return Kind.DEPENDENCY_ANALYSIS;
        }
    }

    /**
     * Every scope named produced within the age on every repository — a plugin not applicable to a
     * repository leaves it out of that scope — and the backlog in those scopes meets the thresholds.
     */
    record FindingsThreshold(List<ToolScope> scopes, int maxAgeDays, Map<Severity, SeverityThreshold> thresholds)
            implements ChecklistRule {

        public FindingsThreshold {
            requireAge(maxAgeDays);
            Objects.requireNonNull(scopes, "scopes");
            if (scopes.isEmpty() || scopes.size() > MAX_SCOPES) {
                throw new InvalidInputException("A findings rule names 1 to " + MAX_SCOPES + " scopes.");
            }
            Set<String> keys = new LinkedHashSet<>();
            for (ToolScope scope : scopes) {
                if (!keys.add(scope.key())) {
                    throw new InvalidInputException("The scope " + scope.key() + " is named twice.");
                }
            }
            scopes = scopes.stream().sorted((a, b) -> a.key().compareTo(b.key())).toList();
            thresholds = orderedThresholds(thresholds);
            if (thresholds.isEmpty()) {
                throw new InvalidInputException("A findings rule states a threshold for at least one severity — "
                        + "\"no plaintext secret\" is every count at zero.");
            }
        }

        @Override
        public Kind kind() {
            return Kind.FINDINGS_THRESHOLD;
        }
    }

    /**
     * The newest coverage import of each repository within the age, its ratio at least the minimum —
     * over the whole report, or over the packages its scope names.
     *
     * @param scope empty to measure the report's totals, exactly as before scopes existed; present to
     *     measure the packages it matches, which the import must have kept
     */
    record CoverageThreshold(int maxAgeDays, Metric metric, BigDecimal minimumRatio, Aggregation aggregation,
            Optional<CoverageScope> scope) implements ChecklistRule {

        public CoverageThreshold {
            requireAge(maxAgeDays);
            Objects.requireNonNull(metric, "metric");
            Objects.requireNonNull(aggregation, "aggregation");
            Objects.requireNonNull(scope, "scope");
            minimumRatio = Ratios.require(Objects.requireNonNull(minimumRatio, "minimumRatio"), "minimumRatio", false);
        }

        /** Over the whole report. */
        public CoverageThreshold(int maxAgeDays, Metric metric, BigDecimal minimumRatio, Aggregation aggregation) {
            this(maxAgeDays, metric, minimumRatio, aggregation, Optional.empty());
        }

        @Override
        public Kind kind() {
            return Kind.COVERAGE_THRESHOLD;
        }
    }

    /**
     * The newest test report of each repository within the age: at least one suite matches the
     * pattern, those that match ran at least the minimum of tests, skipped ones not counted, and none
     * failed nor errored.
     *
     * @param suitePattern a glob over the suite's whole name — {@code *} any run, {@code ?} one character
     */
    record TestSuitePassed(int maxAgeDays, String suitePattern, int minimumTests) implements ChecklistRule {

        public TestSuitePassed {
            requireAge(maxAgeDays);
            String pattern = suitePattern == null ? "" : suitePattern.strip();
            if (pattern.isEmpty() || pattern.length() > MAX_PATTERN || pattern.chars().anyMatch(Character::isISOControl)) {
                throw new InvalidInputException("suitePattern names the suites, 1 to " + MAX_PATTERN
                        + " characters — com.example.arch.*, * for any run and ? for one character.");
            }
            if (minimumTests < 1 || minimumTests > MAX_TESTS) {
                throw new InvalidInputException("minimumTests is at least 1: a suite that ran nothing proves nothing.");
            }
            suitePattern = pattern;
        }

        @Override
        public Kind kind() {
            return Kind.TEST_SUITE_PASSED;
        }
    }

    /**
     * Every declared package present, on every repository, in the SBOM of its newest scan whose
     * dependency step produced within the age, and at one of the versions allowed — every occurrence
     * whose version the SBOM states. An occurrence stating none is named, not judged; a package none of
     * whose occurrences states one is {@link NoDataReason#VERSION_UNRECORDED}, never a failure.
     */
    record ComponentVersions(int maxAgeDays, List<AllowedComponent> components) implements ChecklistRule {

        public ComponentVersions {
            requireAge(maxAgeDays);
            Objects.requireNonNull(components, "components");
            if (components.isEmpty() || components.size() > MAX_COMPONENTS) {
                throw new InvalidInputException("A component rule declares 1 to " + MAX_COMPONENTS + " packages.");
            }
            Set<String> prefixes = new LinkedHashSet<>();
            for (AllowedComponent component : components) {
                if (!prefixes.add(component.purlPrefix())) {
                    throw new InvalidInputException("The package " + component.purlPrefix() + " is declared twice.");
                }
            }
            components = components.stream().sorted((a, b) -> a.purlPrefix().compareTo(b.purlPrefix())).toList();
        }

        @Override
        public Kind kind() {
            return Kind.COMPONENT_VERSIONS;
        }
    }

    enum Metric {
        LINE,
        BRANCH;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** Per repository, each its own ratio; or the project's lines summed, weighted by their size. */
    enum Aggregation {
        PER_REPOSITORY,
        PROJECT_WEIGHTED;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    // ------------------------------------------------------------------ the canonical form

    /** Keys sorted, no whitespace: the stored bound rule, and what the content digest reads. */
    default String canonical() {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("kind", kind().wireName());
        node.put("maxAgeDays", maxAgeDays());
        switch (this) {
            case DependencyAnalysis rule -> {
                node.put("requireSchedule", rule.requireSchedule());
                if (!rule.thresholds().isEmpty()) {
                    node.set("thresholds", thresholdsNode(rule.thresholds()));
                }
            }
            case FindingsThreshold rule -> {
                ArrayNode scopes = node.putArray("scopes");
                rule.scopes().forEach(scope -> scopes.add(scope.key()));
                node.set("thresholds", thresholdsNode(rule.thresholds()));
            }
            case CoverageThreshold rule -> {
                node.put("metric", rule.metric().wireName());
                node.put("minimumRatio", rule.minimumRatio());
                node.put("aggregation", rule.aggregation().wireName());
                // Only when present: a rule bound before scopes existed keeps its bytes, and its digest.
                rule.scope().ifPresent(scope -> {
                    ObjectNode written = node.putObject("scope");
                    if (!scope.include().isEmpty()) {
                        scope.include().forEach(written.putArray("include")::add);
                    }
                    if (!scope.exclude().isEmpty()) {
                        scope.exclude().forEach(written.putArray("exclude")::add);
                    }
                });
            }
            case TestSuitePassed rule -> {
                node.put("suitePattern", rule.suitePattern());
                node.put("minimumTests", rule.minimumTests());
            }
            case ComponentVersions rule -> {
                ArrayNode components = node.putArray("components");
                for (AllowedComponent component : rule.components()) {
                    ObjectNode entry = components.addObject();
                    entry.put("purlPrefix", component.purlPrefix());
                    ArrayNode versions = entry.putArray("versions");
                    component.versions().forEach(versions::add);
                }
            }
        }
        try {
            return Json.WRITER.writeValueAsString(sorted(node));
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A rule could not be written.", impossible);
        }
    }

    /** SHA-256 of the canonical form: what a measurement names as the rule it applied. */
    default String digest() {
        return Digests.sha256Hex(canonical());
    }

    // ------------------------------------------------------------------ reading

    /** A rule as a request states it, refused in words — a key another kind takes is refused, never ignored. */
    static ChecklistRule parse(JsonNode node) {
        return read(node, true);
    }

    /**
     * {@code stated} is a person binding the rule now; otherwise it is a stored canonical form read back,
     * which a check added after it was bound must not refuse — its text is its digest.
     */
    private static ChecklistRule read(JsonNode node, boolean stated) {
        if (node == null || !node.isObject()) {
            throw new InvalidInputException("A rule is an object: its kind, its maximum age and its parameters.");
        }
        Kind kind = Kind.parse(text(node, "kind").orElse(null));
        int maxAge = integer(node, "maxAgeDays").orElseThrow(() -> new InvalidInputException("State the rule's "
                + "maximum age, maxAgeDays — how old its evidence may be; a rule without one is refused."));
        Set<String> allowed = switch (kind) {
            case DEPENDENCY_ANALYSIS -> Set.of("requireSchedule", "thresholds");
            case FINDINGS_THRESHOLD -> Set.of("scopes", "thresholds");
            case COVERAGE_THRESHOLD -> Set.of("metric", "minimumRatio", "aggregation", "scope");
            case TEST_SUITE_PASSED -> Set.of("suitePattern", "minimumTests");
            case COMPONENT_VERSIONS -> Set.of("components");
        };
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            if (field.getValue().isNull() || field.getKey().equals("kind") || field.getKey().equals("maxAgeDays")) {
                continue;
            }
            if (!allowed.contains(field.getKey())) {
                throw new InvalidInputException("A " + kind.wireName() + " rule takes no \""
                        + BoundedText.clip(field.getKey(), 40) + "\"; it takes " + String.join(", ", new java.util.TreeSet<>(allowed))
                        + ".");
            }
        }
        return switch (kind) {
            case DEPENDENCY_ANALYSIS -> new DependencyAnalysis(maxAge,
                    bool(node, "requireSchedule").orElseThrow(() -> new InvalidInputException("State whether the "
                            + "repository's schedule must match the maximum age, requireSchedule — true or false.")),
                    thresholds(node.get("thresholds")));
            case FINDINGS_THRESHOLD -> new FindingsThreshold(scopes(node.get("scopes")), maxAge,
                    thresholds(node.get("thresholds")));
            case COVERAGE_THRESHOLD -> new CoverageThreshold(maxAge,
                    named(Metric.values(), Metric::wireName, text(node, "metric").orElse(null), "metric"),
                    decimal(node, "minimumRatio").orElseThrow(() -> new InvalidInputException("State the minimum "
                            + "coverage, minimumRatio — 0.8 for 80 %.")),
                    named(Aggregation.values(), Aggregation::wireName, text(node, "aggregation").orElse(null),
                            "aggregation"),
                    coverageScope(node.get("scope")));
            case TEST_SUITE_PASSED -> new TestSuitePassed(maxAge, text(node, "suitePattern").orElse(null),
                    integer(node, "minimumTests").orElseThrow(() -> new InvalidInputException("State the least number "
                            + "of tests the matching suites must run, minimumTests.")));
            case COMPONENT_VERSIONS -> new ComponentVersions(maxAge, components(node.get("components"), stated));
        };
    }

    /** A stored canonical form read back — written by {@link #canonical()}, so a refusal is a defect. */
    static ChecklistRule fromCanonical(String canonical) {
        try {
            return read(Json.READER.readTree(canonical), false);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("A stored rule does not read as JSON.", unreadable);
        }
    }

    /** A rule as a request states it, as JSON text. */
    static ChecklistRule parse(String json) {
        try {
            return parse(Json.READER.readTree(json == null ? "" : json));
        } catch (JsonProcessingException unreadable) {
            throw new InvalidInputException("A rule is a JSON object; this one does not read.");
        }
    }

    private static void requireAge(int maxAgeDays) {
        if (maxAgeDays < 1 || maxAgeDays > MAX_AGE_DAYS) {
            throw new InvalidInputException("maxAgeDays is between 1 and " + MAX_AGE_DAYS + "; " + maxAgeDays
                    + " is not.");
        }
    }

    private static Map<Severity, SeverityThreshold> orderedThresholds(Map<Severity, SeverityThreshold> thresholds) {
        Objects.requireNonNull(thresholds, "thresholds");
        EnumMap<Severity, SeverityThreshold> ordered = new EnumMap<>(Severity.class);
        ordered.putAll(thresholds);
        return java.util.Collections.unmodifiableMap(ordered);
    }

    private static Map<Severity, SeverityThreshold> thresholds(JsonNode node) {
        Map<Severity, SeverityThreshold> thresholds = new EnumMap<>(Severity.class);
        if (node == null || node.isNull()) {
            return thresholds;
        }
        if (!node.isObject()) {
            throw new InvalidInputException("thresholds is an object: each severity, and what it may hold.");
        }
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            Severity severity = named(Severity.values(), Severity::wireName, field.getKey(), "severity");
            JsonNode threshold = field.getValue();
            if (threshold == null || !threshold.isObject()) {
                throw new InvalidInputException("The " + severity.wireName() + " threshold is an object — maxOpen, "
                        + "minResolvedRatio.");
            }
            for (Iterator<String> names = threshold.fieldNames(); names.hasNext(); ) {
                String name = names.next();
                if (!name.equals("maxOpen") && !name.equals("minResolvedRatio") && !threshold.get(name).isNull()) {
                    throw new InvalidInputException("A severity's threshold takes maxOpen and minResolvedRatio; \""
                            + BoundedText.clip(name, 40) + "\" is neither.");
                }
            }
            thresholds.put(severity, new SeverityThreshold(integer(threshold, "maxOpen"),
                    decimal(threshold, "minResolvedRatio")));
        }
        return thresholds;
    }

    private static List<ToolScope> scopes(JsonNode node) {
        if (node == null || !node.isArray()) {
            throw new InvalidInputException("A findings rule names its scopes — builtin:sast, plugin:<id>, "
                    + "import:<source>/<tool>.");
        }
        List<ToolScope> scopes = new ArrayList<>();
        for (JsonNode scope : node) {
            if (!scope.isTextual()) {
                throw new InvalidInputException("A scope is a string, builtin:<step>, plugin:<id> or import:<source>/<tool>.");
            }
            scopes.add(ToolScope.parse(scope.asText()));
        }
        return scopes;
    }

    /** {@code {"include": [...], "exclude": [...]}}, either list optional; absent or null is no scope. */
    private static Optional<CoverageScope> coverageScope(JsonNode node) {
        if (node == null || node.isNull()) {
            return Optional.empty();
        }
        if (!node.isObject()) {
            throw new InvalidInputException("scope is an object — include and exclude, each a list of patterns "
                    + "over package paths, **/service/**.");
        }
        for (Map.Entry<String, JsonNode> field : node.properties()) {
            if (!field.getKey().equals("include") && !field.getKey().equals("exclude") && !field.getValue().isNull()) {
                throw new InvalidInputException("A coverage scope takes include and exclude; \""
                        + BoundedText.clip(field.getKey(), 40) + "\" is neither.");
            }
        }
        return Optional.of(new CoverageScope(patternList(node.get("include"), "include"),
                patternList(node.get("exclude"), "exclude")));
    }

    private static List<String> patternList(JsonNode node, String what) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            throw new InvalidInputException("The coverage scope's " + what + " is a list of patterns.");
        }
        List<String> patterns = new ArrayList<>();
        for (JsonNode pattern : node) {
            if (!pattern.isTextual()) {
                throw new InvalidInputException("A pattern in the coverage scope's " + what + " is a string.");
            }
            patterns.add(pattern.asText());
        }
        return patterns;
    }

    private static List<AllowedComponent> components(JsonNode node, boolean stated) {
        if (node == null || !node.isArray()) {
            throw new InvalidInputException("A component rule declares its packages, components: each a purlPrefix "
                    + "and its allowed versions.");
        }
        List<AllowedComponent> components = new ArrayList<>();
        for (JsonNode component : node) {
            if (component == null || !component.isObject()) {
                throw new InvalidInputException("A declared package is an object, purlPrefix and versions.");
            }
            JsonNode versions = component.get("versions");
            if (versions == null || !versions.isArray()) {
                throw new InvalidInputException("A declared package lists its allowed versions, versions.");
            }
            List<String> allowed = new ArrayList<>();
            versions.forEach(version -> {
                if (!version.isTextual()) {
                    throw new InvalidInputException("An allowed version is a string, as the SBOM writes it.");
                }
                allowed.add(version.asText());
            });
            String prefix = text(component, "purlPrefix").orElse("");
            components.add(stated ? AllowedComponent.declared(prefix, allowed) : new AllowedComponent(prefix, allowed));
        }
        return components;
    }

    private static <E> E named(E[] values, java.util.function.Function<E, String> wireName, String value, String what) {
        String wanted = value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
        return Arrays.stream(values).filter(candidate -> wireName.apply(candidate).equals(wanted)).findFirst()
                .orElseThrow(() -> new InvalidInputException("A rule's " + what + " is one of "
                        + Arrays.stream(values).map(wireName).collect(Collectors.joining(", "))
                        + (wanted.isEmpty() ? "; none was given." : "; \"" + BoundedText.clip(wanted, 40) + "\" is not one.")));
    }

    private static Optional<String> text(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            return Optional.empty();
        }
        if (!value.isTextual()) {
            throw new InvalidInputException(name + " is a string.");
        }
        return Optional.of(value.asText());
    }

    private static Optional<Integer> integer(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            return Optional.empty();
        }
        if (!value.isIntegralNumber() || !value.canConvertToInt()) {
            throw new InvalidInputException(name + " is a whole number.");
        }
        return Optional.of(value.intValue());
    }

    private static Optional<Boolean> bool(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            return Optional.empty();
        }
        if (!value.isBoolean()) {
            throw new InvalidInputException(name + " is true or false.");
        }
        return Optional.of(value.booleanValue());
    }

    private static Optional<BigDecimal> decimal(JsonNode node, String name) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            return Optional.empty();
        }
        if (!value.isNumber()) {
            throw new InvalidInputException(name + " is a number — 0.6 for 60 %.");
        }
        return Optional.of(value.decimalValue());
    }

    private static ObjectNode thresholdsNode(Map<Severity, SeverityThreshold> thresholds) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        thresholds.forEach((severity, threshold) -> {
            ObjectNode entry = node.putObject(severity.wireName());
            threshold.maxOpen().ifPresent(max -> entry.put("maxOpen", max));
            threshold.minResolvedRatio().ifPresent(ratio -> entry.put("minResolvedRatio", ratio));
        });
        return node;
    }

    /** The node with every object's keys in order, recursively: the canonical form's one writing. */
    private static JsonNode sorted(JsonNode node) {
        if (node.isObject()) {
            TreeMap<String, JsonNode> fields = new TreeMap<>();
            node.properties().forEach(field -> fields.put(field.getKey(), sorted(field.getValue())));
            ObjectNode ordered = JsonNodeFactory.instance.objectNode();
            fields.forEach(ordered::set);
            return ordered;
        }
        if (node.isArray()) {
            ArrayNode ordered = JsonNodeFactory.instance.arrayNode();
            node.forEach(element -> ordered.add(sorted(element)));
            return ordered;
        }
        return node;
    }

    /** One reader and one writer: decimals read as decimals, so 0.6 is never a double on its way in. */
    final class Json {
        static final ObjectMapper READER = new ObjectMapper()
                .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        static final ObjectMapper WRITER = new ObjectMapper();

        private Json() {}
    }
}

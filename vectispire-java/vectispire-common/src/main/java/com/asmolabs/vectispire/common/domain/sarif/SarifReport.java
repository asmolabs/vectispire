package com.asmolabs.vectispire.common.domain.sarif;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * A SARIF 2.1.0 log, read with the guards every document from outside this process gets.
 *
 * <p>Two producers: a plugin container, which read a repository somebody else wrote and may have
 * been steered by it, and an internal tool uploading through a declared source. Neither is trusted
 * with the shape of what it hands over.
 *
 * <h2>The guards</h2>
 *
 * <ul>
 *   <li><b>A size ceiling, checked before a byte is parsed</b> — the caller's: the scanner limits'
 *       output ceiling for a plugin, the route's for an import.
 *   <li><b>No expansion.</b> JSON has no entity to expand, which is the XML hazard; its equivalent
 *       is a document built to cost more to read than to send. Nesting is capped at
 *       {@value #MAX_DEPTH}, a string at {@value #MAX_STRING} characters, a number at
 *       {@value #MAX_NUMBER} digits, and the whole log at {@value #MAX_RUNS} runs and
 *       {@value #MAX_RESULTS} results. A key given twice is refused rather than resolved by whichever
 *       the parser keeps.
 *   <li><b>No link.</b> {@code externalPropertyFileReferences} and {@code inlineExternalProperties}
 *       point at content held elsewhere; a location outside the analysed tree names a file this
 *       product never saw ({@link SarifPaths}). Both refuse the document.
 * </ul>
 *
 * <h2>Absent is not empty, here too</h2>
 *
 * <p>SARIF says it itself: a run whose {@code results} property is <em>absent</em> did not compute
 * results; an empty array means it found nothing. That maps onto decision 0007 without
 * interpretation, so {@link Run#results()} is an {@link Optional}. A run whose invocation says
 * {@code "executionSuccessful": false} is read the same way by the callers: it is a tool telling us
 * it failed, whatever it managed to write.
 */
public final class SarifReport {

    static final int MAX_DEPTH = 64;
    static final int MAX_STRING = 1_000_000;
    static final int MAX_NUMBER = 100;
    static final int MAX_RUNS = 20;
    static final int MAX_RESULTS = 100_000;

    /** Longer than any rule identifier worth keeping; the whole value enters the fingerprint. */
    static final int MAX_RULE_ID = 1_000;

    /** A tool name is part of an imported issue's tool key, so it is bounded rather than clipped. */
    public static final int MAX_TOOL_NAME = 100;

    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(MAX_DEPTH)
                    .maxStringLength(MAX_STRING)
                    .maxNumberLength(MAX_NUMBER)
                    .build())
            .enable(com.fasterxml.jackson.core.StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build());

    /**
     * @param toolName {@code tool.driver.name}, required
     * @param toolVersion {@code semanticVersion}, else {@code version}, else {@code null}
     * @param successful false when an invocation says {@code executionSuccessful: false}
     * @param results absent when the run carries no {@code results} property: it did not compute any
     */
    public record Run(String toolName, String toolVersion, boolean successful, Optional<List<SarifFinding>> results) {}

    private final List<Run> runs;

    private SarifReport(List<Run> runs) {
        this.runs = List.copyOf(runs);
    }

    public List<Run> runs() {
        return runs;
    }

    /**
     * Reads a log.
     *
     * @param maxBytes past this the document is refused unread
     * @param absoluteRoots the absolute directories standing for the analysed tree — see
     *     {@link SarifPaths#normalize}; empty for a document whose producer's checkout is unknown
     * @throws InvalidSarifException with a reason meant for the producer
     */
    public static SarifReport read(byte[] document, long maxBytes, List<String> absoluteRoots) {
        if (document == null || document.length == 0) {
            throw new InvalidSarifException("The SARIF document is empty.");
        }
        if (document.length > maxBytes) {
            throw new InvalidSarifException("The SARIF document is larger than the " + maxBytes + " bytes accepted.");
        }
        JsonNode root;
        try (JsonParser parser = MAPPER.createParser(document)) {
            root = MAPPER.readTree(parser);
            if (parser.nextToken() != null) {
                throw new InvalidSarifException("The SARIF document carries content after its end.");
            }
        } catch (IOException unreadable) {
            throw new InvalidSarifException("The SARIF document is not readable JSON: " + firstLine(unreadable.getMessage()));
        }
        if (root == null || !root.isObject()) {
            throw new InvalidSarifException("A SARIF document is a JSON object.");
        }
        if (!"2.1.0".equals(root.path("version").asText(null))) {
            throw new InvalidSarifException("Only SARIF 2.1.0 is read; this document says version \""
                    + root.path("version").asText("") + "\".");
        }
        if (present(root.get("inlineExternalProperties"))) {
            throw new InvalidSarifException("The SARIF document refers to external properties; they are not followed.");
        }
        JsonNode runs = root.get("runs");
        if (runs == null || !runs.isArray()) {
            throw new InvalidSarifException("A SARIF document carries a \"runs\" array.");
        }
        if (runs.size() > MAX_RUNS) {
            throw new InvalidSarifException("The SARIF document carries more than " + MAX_RUNS + " runs.");
        }

        int[] budget = {MAX_RESULTS};
        List<Run> read = new ArrayList<>(runs.size());
        for (JsonNode run : runs) {
            read.add(run(run, absoluteRoots, budget));
        }
        return new SarifReport(read);
    }

    private static Run run(JsonNode run, List<String> roots, int[] budget) {
        if (!run.isObject()) {
            throw new InvalidSarifException("A SARIF run is a JSON object.");
        }
        if (present(run.get("externalPropertyFileReferences"))) {
            throw new InvalidSarifException("A SARIF run refers to external property files; they are not followed.");
        }
        JsonNode driver = run.path("tool").path("driver");
        String toolName = driver.path("name").isTextual() ? driver.get("name").asText().strip() : "";
        if (toolName.isEmpty()) {
            throw new InvalidSarifException("A SARIF run names no tool (tool.driver.name).");
        }
        if (toolName.length() > MAX_TOOL_NAME || hasControl(toolName)) {
            throw new InvalidSarifException("The tool name of a SARIF run is longer than " + MAX_TOOL_NAME
                    + " characters or carries a control character.");
        }
        String version = text(driver, "semanticVersion").or(() -> text(driver, "version")).orElse(null);

        boolean successful = true;
        for (JsonNode invocation : run.path("invocations")) {
            if (invocation.path("executionSuccessful").isBoolean() && !invocation.get("executionSuccessful").asBoolean()) {
                successful = false;
            }
        }

        JsonNode results = run.get("results");
        if (results == null || results.isNull()) {
            return new Run(toolName, version, successful, Optional.empty());
        }
        if (!results.isArray()) {
            throw new InvalidSarifException("The \"results\" of a SARIF run are an array.");
        }
        budget[0] -= results.size();
        if (budget[0] < 0) {
            throw new InvalidSarifException("The SARIF document carries more than " + MAX_RESULTS + " results.");
        }

        Rules rules = Rules.of(driver.path("rules"));
        List<SarifFinding> findings = new ArrayList<>(results.size());
        int index = 0;
        for (JsonNode result : results) {
            finding(result, rules, roots, index++).ifPresent(findings::add);
        }
        return new Run(toolName, version, successful, Optional.of(List.copyOf(findings)));
    }

    /** A result as a finding, or empty for one SARIF itself says is not a finding. */
    private static Optional<SarifFinding> finding(JsonNode result, Rules rules, List<String> roots, int index) {
        if (!result.isObject()) {
            throw new InvalidSarifException("Result " + index + " is not a JSON object.");
        }
        // `pass` and `notApplicable` are the tool saying there is nothing here; the other kinds
        // (`fail`, the default, `review`, `open`, `informational`) describe something to look at.
        String kind = result.path("kind").asText("fail");
        if (kind.equals("pass") || kind.equals("notApplicable")) {
            return Optional.empty();
        }
        // A suppression the producer accepted — the default status — is a decision already taken
        // where the report was made. Importing it as an open issue would undo that decision here,
        // with nobody's name on it.
        for (JsonNode suppression : result.path("suppressions")) {
            String status = suppression.path("status").asText("accepted");
            if (status.equals("accepted")) {
                return Optional.empty();
            }
        }

        JsonNode rule = rules.ruleOf(result);
        String ruleId = text(result, "ruleId")
                .or(() -> text(result.path("rule"), "id"))
                .or(() -> text(rule, "id"))
                .orElseThrow(() -> new InvalidSarifException("Result " + index + " names no rule: without one it "
                        + "has no identity across runs, and every run would open it again."));
        if (ruleId.length() > MAX_RULE_ID || hasControl(ruleId)) {
            throw new InvalidSarifException("Result " + index + " has a rule identifier longer than " + MAX_RULE_ID
                    + " characters or carrying a control character.");
        }

        JsonNode location = result.path("locations").path(0).path("physicalLocation");
        JsonNode artifact = location.path("artifactLocation");
        String file = SarifPaths.normalize(artifact.path("uri").asText(null), roots);
        Integer line = location.path("region").path("startLine").canConvertToInt()
                && location.path("region").path("startLine").asInt() > 0
                ? location.path("region").path("startLine").asInt()
                : null;

        String message = text(result.path("message"), "text")
                .or(() -> text(rule.path("shortDescription"), "text"))
                .or(() -> text(rule.path("fullDescription"), "text"))
                .orElse(null);

        return Optional.of(new SarifFinding(ruleId, severity(result, rule), file, line, message));
    }

    /**
     * The severity, from the most specific statement the producer made.
     *
     * <p>{@code security-severity} first — the numeric score GitHub's convention puts in a rule's or a
     * result's properties, on the CVSS scale — then the SARIF level, of the result and then of the
     * rule's default configuration. SARIF's own default level is {@code warning}.
     *
     * <p>{@code note} and {@code none} are low, not negligible: a tool emitting only notes is still
     * reporting something, and {@code NEGLIGIBLE} ranks below every threshold a policy offers.
     */
    static Severity severity(JsonNode result, JsonNode rule) {
        Optional<Double> score = score(result.path("properties").path("security-severity"))
                .or(() -> score(rule.path("properties").path("security-severity")));
        if (score.isPresent()) {
            double value = score.get();
            if (value >= 9.0) {
                return Severity.CRITICAL;
            }
            if (value >= 7.0) {
                return Severity.HIGH;
            }
            if (value >= 4.0) {
                return Severity.MEDIUM;
            }
            return Severity.LOW;
        }
        String level = text(result, "level")
                .or(() -> text(rule.path("defaultConfiguration"), "level"))
                .orElse("warning")
                .toLowerCase(Locale.ROOT);
        return switch (level) {
            case "error" -> Severity.HIGH;
            case "note", "none" -> Severity.LOW;
            default -> Severity.MEDIUM;
        };
    }

    private static Optional<Double> score(JsonNode value) {
        try {
            double parsed = value.isNumber() ? value.asDouble() : value.isTextual() ? Double.parseDouble(value.asText().strip()) : Double.NaN;
            return Double.isFinite(parsed) && parsed >= 0 && parsed <= 10 ? Optional.of(parsed) : Optional.empty();
        } catch (NumberFormatException notAScore) {
            return Optional.empty();
        }
    }

    /** The driver's rules, reachable by index and by identifier. */
    private record Rules(List<JsonNode> byIndex, Map<String, JsonNode> byId) {

        static Rules of(JsonNode rules) {
            List<JsonNode> byIndex = new ArrayList<>();
            Map<String, JsonNode> byId = new HashMap<>();
            for (JsonNode rule : rules) {
                byIndex.add(rule);
                text(rule, "id").ifPresent(id -> byId.putIfAbsent(id, rule));
            }
            return new Rules(byIndex, byId);
        }

        JsonNode ruleOf(JsonNode result) {
            JsonNode index = result.path("ruleIndex").isInt() ? result.get("ruleIndex") : result.path("rule").path("index");
            if (index.isInt() && index.asInt() >= 0 && index.asInt() < byIndex.size()) {
                return byIndex.get(index.asInt());
            }
            Optional<String> id = text(result, "ruleId");
            return id.map(byId::get).orElse(com.fasterxml.jackson.databind.node.MissingNode.getInstance());
        }
    }

    private static Optional<String> text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || !value.isTextual()) {
            return Optional.empty();
        }
        String text = value.asText().strip();
        return text.isEmpty() ? Optional.empty() : Optional.of(text);
    }

    private static boolean present(JsonNode node) {
        return node != null && !node.isNull() && !(node.isContainerNode() && node.isEmpty());
    }

    private static boolean hasControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static String firstLine(String message) {
        if (message == null) {
            return "no detail";
        }
        int newline = message.indexOf('\n');
        String line = newline < 0 ? message : message.substring(0, newline);
        return line.length() <= 200 ? line : line.substring(0, 200) + "…";
    }
}

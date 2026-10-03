package com.asmolabs.vectispire.common.domain.sbom;

import com.asmolabs.vectispire.common.domain.reports.InvalidReportException;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A CycloneDX JSON SBOM produced by a build — {@code cyclonedx-maven-plugin}'s {@code makeAggregateBom},
 * the Gradle CycloneDX plugin — read with the guards every document from outside this process gets.
 *
 * <p><b>Why a build's SBOM at all.</b> The scanner reads a source tree: for Maven it reads the poms, so a
 * version managed by a parent or a BOM comes out as {@code UNKNOWN} and a library pulled in transitively
 * is not listed at all. A checklist line asking "is library X used, and at which version" then answers a
 * false "no". The build resolved the graph; its SBOM states what it packaged.
 *
 * <h2>The guards</h2>
 *
 * <ul>
 *   <li><b>A size ceiling, checked before a byte is parsed</b> — the route's.
 *   <li><b>No expansion.</b> Nesting is capped at {@value #MAX_DEPTH}, a string at {@value #MAX_STRING}
 *       characters, a number at {@value #MAX_NUMBER} digits, the components at {@value #MAX_COMPONENTS},
 *       nested ones included. A key given twice is refused rather than resolved by whichever the parser
 *       keeps, and content after the document's end is refused.
 *   <li><b>No link followed.</b> {@code externalReferences}, a {@code bom-link} in the dependency graph, a
 *       {@code $schema}: nothing here fetches anything. What the document states inline is what is read,
 *       and a component held by reference elsewhere is simply not in it.
 *   <li><b>CycloneDX 1.4 to 1.6, JSON</b>: {@code bomFormat} must say {@code CycloneDX} and {@code
 *       specVersion} one of {@link #SPEC_VERSIONS}. A Syft document, an SPDX one or a CycloneDX XML file
 *       sent with the wrong type is refused in words, never guessed at.
 * </ul>
 *
 * <h2>Absent is not empty, here too</h2>
 *
 * <p>A BOM without a {@code components} property listed nothing it can be held to, and is refused; an
 * empty array is a build with no dependency, which is an answer (decision 0007). A component's value the
 * columns cannot hold — a name past {@value #MAX_NAME} characters, a purl past {@value #MAX_PURL} — is
 * refused rather than cut: a clipped purl names another package.
 */
public record BuildSbom(String specVersion, Optional<String> tool, List<Component> components) {

    /** The CycloneDX versions read: 1.4 is the oldest the Maven and Gradle plugins still write by default. */
    public static final Set<String> SPEC_VERSIONS = Set.of("1.4", "1.5", "1.6");

    static final int MAX_DEPTH = 64;
    static final int MAX_STRING = 1_000_000;
    static final int MAX_NUMBER = 100;

    /** A large aggregate BOM lists a few thousand; this is ten times the largest measured, and a ceiling. */
    public static final int MAX_COMPONENTS = 50_000;

    /** The inventory's columns: {@code t_component} and {@code t_build_sbom_component}. */
    public static final int MAX_NAME = 255;
    public static final int MAX_VERSION = 255;
    public static final int MAX_PURL = 500;
    public static final int MAX_TYPE = 50;
    public static final int MAX_LICENSE = 255;
    public static final int MAX_TOOL = 200;

    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(MAX_DEPTH)
                    .maxStringLength(MAX_STRING)
                    .maxNumberLength(MAX_NUMBER)
                    .build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build());

    /**
     * One component the build listed.
     *
     * @param version null where the build states none
     * @param purl canonical: a Maven purl's default {@code type=jar} qualifier is dropped, so that the
     *     plugin's {@code pkg:maven/g/a@1.0?type=jar} and the scanner's {@code pkg:maven/g/a@1.0} are one
     *     package; null where the build gives none
     * @param type CycloneDX's component type ({@code library}, {@code framework}…), or null
     * @param license the declared licences joined by {@code OR}, as the scanner's are, or null
     */
    public record Component(String name, String version, String purl, String type, String license) {}

    public BuildSbom {
        components = List.copyOf(components);
    }

    /**
     * Reads a document.
     *
     * @param maxBytes past this the document is refused unread
     * @throws InvalidReportException with a reason meant for the pipeline that produced it
     */
    public static BuildSbom read(byte[] document, long maxBytes) {
        if (document == null || document.length == 0) {
            throw new InvalidReportException("The SBOM is empty.");
        }
        if (document.length > maxBytes) {
            throw new InvalidReportException("The SBOM is larger than the " + maxBytes + " bytes accepted.");
        }
        JsonNode root;
        try (JsonParser parser = MAPPER.createParser(document)) {
            root = MAPPER.readTree(parser);
            if (parser.nextToken() != null) {
                throw new InvalidReportException("The SBOM carries content after its end.");
            }
        } catch (IOException unreadable) {
            throw new InvalidReportException("The SBOM is not readable JSON: " + firstLine(unreadable.getMessage()));
        }
        if (root == null || !root.isObject()) {
            throw new InvalidReportException("A CycloneDX SBOM is a JSON object.");
        }
        if (!"CycloneDX".equals(root.path("bomFormat").asText(null))) {
            throw new InvalidReportException("Only CycloneDX JSON is read: the document's \"bomFormat\" is not "
                    + "\"CycloneDX\".");
        }
        String spec = root.path("specVersion").isTextual() ? root.get("specVersion").asText() : "";
        if (!SPEC_VERSIONS.contains(spec)) {
            throw new InvalidReportException("CycloneDX 1.4, 1.5 and 1.6 are read; this document says specVersion \""
                    + clip(spec) + "\".");
        }
        JsonNode listed = root.get("components");
        if (listed == null || listed.isNull()) {
            throw new InvalidReportException("The SBOM has no \"components\": a document that lists nothing is not "
                    + "one that found nothing.");
        }
        if (!listed.isArray()) {
            throw new InvalidReportException("The \"components\" of a CycloneDX SBOM are an array.");
        }
        Map<String, Component> read = new LinkedHashMap<>();
        int[] budget = {MAX_COMPONENTS};
        walk(listed, read, budget, "components");
        return new BuildSbom(spec, tool(root.path("metadata").path("tools")), new ArrayList<>(read.values()));
    }

    /** The components of an array and of every component nested in it, each read once. */
    private static void walk(JsonNode array, Map<String, Component> read, int[] budget, String where) {
        int index = 0;
        for (JsonNode node : array) {
            String at = where + "[" + index++ + "]";
            if (--budget[0] < 0) {
                throw new InvalidReportException("The SBOM lists more than " + MAX_COMPONENTS + " components.");
            }
            if (!node.isObject()) {
                throw new InvalidReportException("Component " + at + " is not a JSON object.");
            }
            Component component = component(node, at);
            // Listed twice — an aggregate BOM naming a library under two modules — is one component.
            read.putIfAbsent(component.purl() != null ? "purl:" + component.purl()
                    : "name:" + component.name() + "@" + component.version(), component);
            JsonNode nested = node.get("components");
            if (nested != null && !nested.isNull()) {
                if (!nested.isArray()) {
                    throw new InvalidReportException("The \"components\" of " + at + " are not an array.");
                }
                walk(nested, read, budget, at + ".components");
            }
        }
    }

    private static Component component(JsonNode node, String at) {
        String name = text(node, "name").orElseThrow(() -> new InvalidReportException("Component " + at
                + " has no name."));
        String version = text(node, "version").orElse(null);
        String purl = text(node, "purl").map(BuildSbom::canonicalPurl).orElse(null);
        String type = text(node, "type").map(value -> value.toLowerCase(Locale.ROOT)).orElse(null);
        String license = license(node.path("licenses"));
        bounded(name, MAX_NAME, at + "'s name");
        bounded(version, MAX_VERSION, at + "'s version");
        bounded(purl, MAX_PURL, at + "'s purl");
        bounded(type, MAX_TYPE, at + "'s type");
        bounded(license, MAX_LICENSE, at + "'s licences");
        if (purl != null && !purl.startsWith("pkg:")) {
            throw new InvalidReportException("The purl of " + at + " does not begin with \"pkg:\".");
        }
        return new Component(name, version, purl, type, license);
    }

    /**
     * The licences a component declares, as the scanner's are read: an SPDX identifier, else a name,
     * else an expression, each entry once, joined by {@code OR}. Null where none is declared — unknown,
     * which the licence inventory counts as such, never as permissive.
     */
    private static String license(JsonNode licenses) {
        if (!licenses.isArray()) {
            return null;
        }
        List<String> values = new ArrayList<>();
        for (JsonNode choice : licenses) {
            Optional<String> value = text(choice.path("license"), "id")
                    .or(() -> text(choice.path("license"), "name"))
                    .or(() -> text(choice, "expression"));
            value.filter(found -> !values.contains(found)).ifPresent(values::add);
        }
        return values.isEmpty() ? null : String.join(" OR ", values);
    }

    /**
     * The tool that wrote the document: {@code metadata.tools} is an array of tools in 1.4, and in 1.5 and
     * 1.6 either that, deprecated, or an object whose {@code components} are the tools.
     */
    private static Optional<String> tool(JsonNode tools) {
        JsonNode list = tools.isObject() ? tools.path("components") : tools;
        for (JsonNode tool : list) {
            Optional<String> name = text(tool, "name");
            if (name.isPresent()) {
                String named = text(tool, "group").or(() -> text(tool, "vendor")).map(group -> group + " ").orElse("")
                        + name.get() + text(tool, "version").map(version -> " " + version).orElse("");
                return Optional.of(named.length() > MAX_TOOL ? named.substring(0, MAX_TOOL) : named);
            }
        }
        return Optional.empty();
    }

    /**
     * A purl with the qualifier the Maven type defaults to taken out — {@code type=jar} is what a Maven
     * purl means when it says nothing, and the scanner says nothing. Any other qualifier stays: a
     * classifier names another artifact.
     */
    static String canonicalPurl(String purl) {
        if (!purl.startsWith("pkg:maven/")) {
            return purl;
        }
        int hash = purl.indexOf('#');
        String subpath = hash < 0 ? "" : purl.substring(hash);
        String head = hash < 0 ? purl : purl.substring(0, hash);
        int question = head.indexOf('?');
        if (question < 0) {
            return purl;
        }
        List<String> kept = new ArrayList<>();
        for (String qualifier : head.substring(question + 1).split("&")) {
            if (!qualifier.isEmpty() && !qualifier.equals("type=jar")) {
                kept.add(qualifier);
            }
        }
        return head.substring(0, question) + (kept.isEmpty() ? "" : "?" + String.join("&", kept)) + subpath;
    }

    private static void bounded(String value, int max, String what) {
        if (value == null) {
            return;
        }
        if (value.length() > max) {
            throw new InvalidReportException("Component " + what + " is longer than " + max + " characters.");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new InvalidReportException("Component " + what + " carries a control character.");
        }
    }

    private static Optional<String> text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() && !value.asText().isBlank()
                ? Optional.of(value.asText().strip())
                : Optional.empty();
    }

    private static String clip(String value) {
        return value.length() > 20 ? value.substring(0, 20) + "…" : value;
    }

    private static String firstLine(String message) {
        if (message == null) {
            return "unreadable";
        }
        int newline = message.indexOf('\n');
        return newline < 0 ? message : message.substring(0, newline);
    }
}

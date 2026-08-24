package com.asmolabs.vectispire.common.scanning;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * What the scanned tree says about itself: its ecosystem, and its own version.
 *
 * <p>Read from the manifest rather than taken from the SBOM, because the SBOM does not carry it.
 * The cataloguer describes a directory by its <em>path</em> — {@code "name": "/repo/source",
 * "version": ""} — and its inventory is the project's dependencies, never the project. The one
 * place the answer exists is the file the ecosystem's own tooling reads.
 *
 * <h2>Absent is not a failure here</h2>
 *
 * <p><b>Unlike an analyser's absent result, an absent manifest is an ordinary outcome</b> and is
 * not reported as a broken step. A repository may legitimately have none — a documentation tree,
 * a collection of scripts — and turning that into a failure would mark such a scan as
 * incomplete for ever. The rule that empty must not be confused with absent belongs to the
 * scanners, whose empty list resolves a backlog; nothing is resolved by a version.
 *
 * <p>For the same reason this is <b>not</b> counted by {@link ScanArtifacts#observedNothing()}:
 * like the SBOM, it describes the target instead of observing it, and a scan that learned only
 * a version number has analysed nothing.
 */
public final class ProjectManifest {

    private ProjectManifest() {}

    /**
     * A version string longer than this is not a version.
     *
     * <p>The column is 255, so this is not about the column: it is about a manifest whose field
     * holds a paragraph — a templated placeholder, a property that never got substituted — which
     * would reach a screen as a wall of text attributed to the project.
     */
    private static final int MAX_VERSION = 100;

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * @param type the ecosystem as an operator names it — {@code maven}, {@code gradle},
     *     {@code npm}, {@code python}
     * @param version the project's own version, or {@code null} when the manifest identifies the
     *     ecosystem without stating one. The type alone is worth keeping: it says what was found
     */
    public record Project(String type, String version) {}

    /**
     * Reads the first manifest recognized at the root of the analysed tree.
     *
     * <p><b>Order matters, and it is the order of authority.</b> A Spring project carries a
     * {@code pom.xml} and often a {@code package.json} for its frontend assets; reporting the
     * latter's version as the project's would be wrong in a way nobody would notice. The build
     * file that produces the artifact comes first.
     *
     * <p>Only the root is looked at, deliberately. A multi-module repository has as many versions
     * as modules, and picking one by walking the tree would pick it by directory order — a
     * stable-looking answer that changes the day somebody renames a folder.
     */
    public static Optional<Project> read(Path source) {
        for (Reader reader : READERS) {
            Path manifest = source.resolve(reader.filename());
            if (!Files.isRegularFile(manifest)) {
                continue;
            }
            try {
                Optional<Project> project = reader.read(manifest, source);
                if (project.isPresent()) {
                    return project;
                }
            } catch (Exception unreadable) {
                // A manifest that is present but broken is still the answer to "which ecosystem":
                // the file's name said it. Its version is what could not be read, and reporting
                // the type without one is more useful — and more honest — than reporting nothing.
                return Optional.of(new Project(reader.type(), null));
            }
        }
        return Optional.empty();
    }

    private interface Reader {
        String filename();

        String type();

        Optional<Project> read(Path manifest, Path source) throws Exception;
    }

    private static final List<Reader> READERS = List.of(
            reader("pom.xml", "maven", (manifest, source) -> maven(manifest)),
            reader("build.gradle.kts", "gradle", (manifest, source) -> gradle(source)),
            reader("build.gradle", "gradle", (manifest, source) -> gradle(source)),
            reader("package.json", "npm", (manifest, source) -> npm(manifest)),
            reader("pyproject.toml", "python", (manifest, source) -> python(manifest)));

    /**
     * Maven states the version on the project, or inherits it from the parent.
     *
     * <p><b>Direct children of the root only.</b> Every {@code <dependency>} carries a
     * {@code <version>} too, and an XPath-free walk that took the first one found in document
     * order would report a dependency's version as the project's — plausible, wrong, and
     * impossible to spot on a screen.
     */
    private static Optional<Project> maven(Path manifest) throws Exception {
        Document document = documents().newDocumentBuilder().parse(manifest.toFile());
        Element root = document.getDocumentElement();

        String version = childText(root, "version");
        if (version == null) {
            Node parent = child(root, "parent");
            version = parent instanceof Element element ? childText(element, "version") : null;
        }
        return Optional.of(new Project("maven", trimmed(version)));
    }

    /**
     * Gradle keeps the version in {@code gradle.properties} far more often than in the build
     * script, where it is an expression this has no business evaluating.
     *
     * <p>Reading the script would mean interpreting Kotlin or Groovy — {@code version =
     * providers.gradleProperty(...)} and the like — so what cannot be read as a literal is
     * reported as an unknown version rather than guessed at.
     */
    private static Optional<Project> gradle(Path source) throws IOException {
        Path properties = source.resolve("gradle.properties");
        if (!Files.isRegularFile(properties)) {
            return Optional.of(new Project("gradle", null));
        }
        Properties values = new Properties();
        try (var stream = Files.newInputStream(properties)) {
            values.load(stream);
        }
        return Optional.of(new Project("gradle", trimmed(values.getProperty("version"))));
    }

    private static Optional<Project> npm(Path manifest) throws IOException {
        JsonNode document = JSON.readTree(Files.readString(manifest, StandardCharsets.UTF_8));
        JsonNode version = document.path("version");
        return Optional.of(new Project("npm", version.isTextual() ? trimmed(version.asText()) : null));
    }

    /**
     * PEP 621's {@code [project]} table, or Poetry's {@code [tool.poetry]}.
     *
     * <p>Matched on the section rather than on the first {@code version =} in the file: a
     * {@code pyproject.toml} is full of them — every pinned dependency, every tool's own
     * configuration — and the first one in document order belongs to whichever table happens to
     * come first. No TOML parser is pulled in for this; a dependency for one field would be a
     * poor trade, and the shape being matched is the one both tools write.
     */
    private static Optional<Project> python(Path manifest) throws IOException {
        String content = Files.readString(manifest, StandardCharsets.UTF_8);
        Matcher matcher = PYTHON_VERSION.matcher(content);
        return Optional.of(new Project("python", matcher.find() ? trimmed(matcher.group(1)) : null));
    }

    private static final Pattern PYTHON_VERSION = Pattern.compile(
            "^\\[(?:project|tool\\.poetry)]\\s*$.*?^\\s*version\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.MULTILINE | Pattern.DOTALL);

    /**
     * A parser that reads no entity and fetches nothing.
     *
     * <p><b>The XML comes from the audited repository</b>, which is the definition of input
     * nobody controls. A {@code pom.xml} carrying a doctype could otherwise read a file off the
     * scanning host — {@code /etc/passwd}, the agent's own configuration — or make the parser
     * open a connection on its author's behalf. Doctypes are refused outright, which settles
     * both without relying on getting the rest of the switches right.
     */
    private static DocumentBuilderFactory documents() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory;
    }

    private static Node child(Element parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Node node = children.item(index);
            if (node.getNodeType() == Node.ELEMENT_NODE && name.equals(node.getNodeName())) {
                return node;
            }
        }
        return null;
    }

    private static String childText(Element parent, String name) {
        Node node = child(parent, name);
        return node == null ? null : node.getTextContent();
    }

    private static String trimmed(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() || trimmed.length() > MAX_VERSION ? null : trimmed;
    }

    private static Reader reader(String filename, String type, ManifestBody body) {
        return new Reader() {
            @Override
            public String filename() {
                return filename;
            }

            @Override
            public String type() {
                return type;
            }

            @Override
            public Optional<Project> read(Path manifest, Path source) throws Exception {
                return body.read(manifest, source);
            }
        };
    }

    @FunctionalInterface
    private interface ManifestBody {
        Optional<Project> read(Path manifest, Path source) throws Exception;
    }
}

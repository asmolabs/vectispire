package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.plugins.ImageDigest;
import com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.sarif.InvalidSarifException;
import com.asmolabs.vectispire.common.domain.sarif.SarifReport;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.LanguageCensus;
import com.asmolabs.vectispire.common.scanning.PluginProvider;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.asmolabs.vectispire.common.scanning.PluginSteps;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The plugin decisions the Rust agent's port is held to (see {@code ReferenceSet}): which manifests an
 * executor believes and what it runs from them, how a plugin's image is relocated to a mirror, which
 * SARIF reports it reads and as which findings, and — end to end through {@link PluginSteps} with a
 * stand-in executor — which state each plugin ends in, with what reason, after asking for which
 * containers.
 *
 * <p><b>The inputs are the files under {@code reference/plugins/<area>/cases.json}</b>, written once and
 * committed; the answers are this side's, under {@code answers.json} beside them. A plugin is code
 * somebody else wrote: a manifest the port believes and Java refuses, a report it reads and Java
 * refuses, or a refusal it reports as "absent" — "unsigned" read as "crashed" — is a confinement
 * lost, so each of those is a case here rather than a sentence in a review.
 *
 * <p>The manifest is read as the agent reads it, with its mapper ({@code AgentProtocol.plugin}:
 * {@code convertValue}, unknown fields ignored). A manifest that mapper cannot read is written
 * {@code "unreadable"} without Jackson's message, which the port does not reproduce.
 */
class PluginsReferenceSetTest {

    /** As {@code VectispireAgentApplication} builds it — see {@code SecretsReferenceSetTest}. */
    private static final ObjectMapper WIRE = JsonMapper.builder()
            .addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
            .addModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    @TempDir
    Path temporary;

    // ----------------------------------------------------------------------------------------------
    // Manifests

    @Test
    void theManifestsAnExecutorBelieves() throws Exception {
        ArrayNode answers = NODES.arrayNode();
        for (JsonNode input : cases("plugins/manifests/cases.json")) {
            ObjectNode answer = answers.addObject();
            answer.put("name", input.get("name").asText());
            PluginManifest manifest;
            try {
                manifest = WIRE.convertValue(input.get("manifest"), PluginManifest.class);
            } catch (IllegalArgumentException unreadable) {
                answer.put("unreadable", true);
                continue;
            }
            // Computed before the validation, as the executor compares it with the task's first.
            answer.put("digest", manifest.digest());
            try {
                manifest.validated();
            } catch (InvalidPluginException refused) {
                answer.put("refused", refused.getMessage());
                continue;
            }
            answer.put("output", manifest.output());
            ArrayNode command = answer.putArray("command");
            manifest.command(PluginManifest.SOURCE, PluginManifest.OUTPUT + "/" + manifest.output()).forEach(command::add);
            ArrayNode exitCodes = answer.putArray("exitCodes");
            manifest.exitCodes().forEach(exitCodes::add);
            ArrayNode languages = answer.putArray("languages");
            manifest.languages().forEach(language -> languages.add(language.wireName()));
            answer.put("network", manifest.network());
            if (manifest.timeoutSeconds() == null) {
                answer.putNull("timeoutSeconds");
            } else {
                answer.put("timeoutSeconds", manifest.timeoutSeconds());
            }
            answer.put("schemaVersion", manifest.schemaVersion());
            if (manifest.signature() == null) {
                answer.putNull("signature");
            } else {
                ObjectNode signature = answer.putObject("signature");
                signature.put("form", manifest.signature().form().name().toLowerCase(java.util.Locale.ROOT));
                ArrayNode fields = signature.putArray("digestFields");
                manifest.signature().digestFields().forEach(fields::add);
            }
        }
        ReferenceSet.expect("plugins/manifests/answers.json", lines(answers));
    }

    @Test
    void theImagesARegistryMirrorServes() throws Exception {
        ArrayNode answers = NODES.arrayNode();
        for (JsonNode input : cases("plugins/images/cases.json")) {
            ObjectNode answer = answers.addObject();
            String reference = input.get("reference").asText();
            String mirror = input.get("mirror").isNull() ? null : input.get("mirror").asText();
            answer.put("reference", reference);
            answer.set("mirror", input.get("mirror"));
            try {
                answer.put("relocated", ImageDigest.relocate(reference, mirror));
            } catch (InvalidPluginException refused) {
                answer.put("refused", refused.getMessage());
            }
            try {
                // What the executor's settings keep of the mirror: blank is none, anything else is checked.
                answer.put("settings", new PluginScanner.Settings(mirror, true).registryMirror());
            } catch (InvalidPluginException refused) {
                answer.put("settingsRefused", refused.getMessage());
            }
            answer.put("registry", ContainerRunner.registryOf(reference));
        }
        ReferenceSet.expect("plugins/images/answers.json", lines(answers));
    }

    // ----------------------------------------------------------------------------------------------
    // SARIF

    @Test
    void theReportsAPluginHandsBack() throws Exception {
        ArrayNode answers = NODES.arrayNode();
        for (JsonNode input : cases("plugins/sarif/cases.json")) {
            ObjectNode answer = answers.addObject();
            answer.put("name", input.get("name").asText());
            byte[] document = document(input).getBytes(StandardCharsets.UTF_8);
            long maxBytes = input.has("maxBytes") ? input.get("maxBytes").asLong() : ScannerLimits.DEFAULT_OUTPUT_BYTES;
            SarifReport report;
            try {
                report = SarifReport.read(document, maxBytes, List.of(PluginManifest.SOURCE));
            } catch (InvalidSarifException refused) {
                answer.put("refused", refused.getMessage());
                continue;
            }
            try {
                Optional<PluginScanner.PluginReport> read = PluginScanner.findings(report, "plugin acme-lint");
                if (read.isEmpty()) {
                    answer.put("absent", true);
                    continue;
                }
                ObjectNode produced = answer.putObject("produced");
                produced.put("toolName", read.get().toolName());
                produced.put("toolVersion", read.get().toolVersion());
                produced.put("findings", WIRE.writeValueAsString(read.get().findings()));
            } catch (ScannerFailureException failed) {
                answer.put("failed", failed.getMessage());
            }
        }
        ReferenceSet.expect("plugins/sarif/answers.json", lines(answers));
    }

    /** The case's document, or the one both sides build for a case too large to commit. */
    static String document(JsonNode input) {
        if (!input.has("repeatedResults")) {
            return input.get("document").asText();
        }
        StringBuilder built = new StringBuilder("{\"version\":\"2.1.0\",\"runs\":[");
        boolean firstRun = true;
        for (JsonNode count : input.get("repeatedResults")) {
            built.append(firstRun ? "" : ",").append("{\"tool\":{\"driver\":{\"name\":\"acme-lint\"}},\"results\":[");
            for (int i = 0; i < count.asInt(); i++) {
                built.append(i == 0 ? "" : ",").append("{\"ruleId\":\"R\",\"kind\":\"pass\"}");
            }
            built.append("]}");
            firstRun = false;
        }
        return built.append("]}").toString();
    }

    // ----------------------------------------------------------------------------------------------
    // Steps, end to end

    @Test
    void theStateEachPluginEndsIn() throws Exception {
        ArrayNode answers = NODES.arrayNode();
        for (JsonNode scenario : cases("plugins/steps/cases.json")) {
            answers.add(scenario(scenario));
        }
        ReferenceSet.expect("plugins/steps/answers.json", lines(answers));
    }

    private ObjectNode scenario(JsonNode scenario) throws Exception {
        Path root = Files.createTempDirectory(temporary, "workspace");
        Workspace workspace = new Workspace(root, root.resolve(Workspace.SOURCE_SUBDIR), root.resolve(Workspace.RULES_SUBDIR));
        if (scenario.get("root").asBoolean()) {
            Files.createDirectories(workspace.source().resolve("app"));
        }
        long outputBytes = scenario.has("outputBytes") ? scenario.get("outputBytes").asLong() : ScannerLimits.DEFAULT_OUTPUT_BYTES;
        StandIn executor = new StandIn(scenario, outputBytes);
        JsonNode settings = scenario.get("settings");
        String owner = scenario.get("owner").isNull() ? null : scenario.get("owner").asText();
        PluginScanner scanner = new PluginScanner(executor,
                new PluginScanner.Settings(settings.get("mirror").isNull() ? null : settings.get("mirror").asText(),
                        settings.get("signatureRequired").asBoolean()),
                directory -> Optional.ofNullable(owner));

        List<PluginRef> references = new ArrayList<>();
        java.util.Map<String, JsonNode> byId = new java.util.HashMap<>();
        for (JsonNode plugin : scenario.get("plugins")) {
            JsonNode manifest = plugin.get("manifest");
            String id = manifest.get("id").asText();
            String digest = plugin.has("digest") ? plugin.get("digest").asText()
                    : WIRE.convertValue(manifest, PluginManifest.class).digest();
            references.add(new PluginRef(id, digest, plugin.get("runsUnsigned").asBoolean()));
            byId.put(id, plugin);
        }
        PluginProvider provider = reference -> {
            JsonNode plugin = byId.get(reference.id());
            PluginManifest manifest = WIRE.convertValue(plugin.get("manifest"), PluginManifest.class);
            return switch (plugin.get("fetch").asText()) {
                case "ok" -> manifest;
                case "null" -> null;
                case "throws" -> throw new IllegalStateException("Plugin " + reference.id() + " refused: HTTP 404");
                case "throwsBare" -> throw new IllegalStateException();
                case "otherId" -> WIRE.convertValue(((ObjectNode) plugin.get("manifest").deepCopy()).put("id", "someone-else"),
                        PluginManifest.class);
                case "otherDigest" -> WIRE.convertValue(((ObjectNode) plugin.get("manifest").deepCopy()).put("name", "Another"),
                        PluginManifest.class);
                default -> throw new IllegalArgumentException(plugin.get("fetch").asText());
            };
        };

        JsonNode census = scenario.get("census");
        Set<Language> found = EnumSet.noneOf(Language.class);
        census.get("found").forEach(language -> found.add(Language.fromWireName(language.asText()).orElseThrow()));
        List<PluginStep> steps = new PluginSteps(scanner, provider).run(references, workspace, workspace.source(),
                new LanguageCensus.Census(found, census.get("complete").asBoolean()));

        ObjectNode answer = NODES.objectNode();
        answer.put("name", scenario.get("name").asText());
        ArrayNode wire = answer.putArray("steps");
        for (PluginStep step : steps) {
            wire.add(WIRE.writeValueAsString(step).replace(root.toString(), "{workspace}"));
        }
        ArrayNode runs = answer.putArray("runs");
        executor.requests.forEach(run -> runs.add(shape(run, root)));
        return answer;
    }

    /** A container request as the port must form it, the workspace written as a placeholder. */
    private static ObjectNode shape(ContainerRun run, Path root) {
        ObjectNode shape = NODES.objectNode();
        shape.put("image", run.image());
        ArrayNode command = shape.putArray("command");
        run.command().forEach(argument -> command.add(argument.replace(root.toString(), "{workspace}")));
        ArrayNode mounts = shape.putArray("mounts");
        for (ContainerRun.Mount mount : run.mounts()) {
            mounts.addObject()
                    .put("source", mount.source().replace(root.toString(), "{workspace}"))
                    .put("target", mount.target())
                    .put("readOnly", mount.readOnly());
        }
        shape.put("label", run.label());
        shape.put("network", run.network());
        shape.put("asRoot", run.asRoot());
        if (run.timeout() == null) {
            shape.putNull("timeoutSeconds");
        } else {
            shape.put("timeoutSeconds", run.timeout().toSeconds());
        }
        shape.put("user", run.user());
        if (run.output() == null) {
            shape.putNull("output");
        } else {
            shape.putObject("output")
                    .put("target", run.output().target())
                    .put("bytes", run.output().bytes())
                    .put("holderImage", run.output().holderImage())
                    .put("file", run.output().file())
                    .put("inodes", run.output().inodes());
        }
        if (run.login() == null) {
            shape.putNull("login");
        } else {
            shape.putObject("login")
                    .put("reference", run.login().reference())
                    .put("directory", run.login().directory().toString().replace(root.toString(), "{workspace}"));
        }
        return shape;
    }

    /**
     * The executor the scenario describes: cosign told apart by its label, as the verifier names it, and
     * the plugin's run answering what the holder's archive and {@code df} would have said.
     */
    private static final class StandIn implements ContainerExecutor {

        private final JsonNode scenario;
        private final long outputBytes;
        final List<ContainerRun> requests = new ArrayList<>();

        StandIn(JsonNode scenario, long outputBytes) {
            this.scenario = scenario;
            this.outputBytes = outputBytes;
        }

        private JsonNode plugin(String label) {
            for (JsonNode plugin : scenario.get("plugins")) {
                String id = plugin.get("manifest").get("id").asText();
                if (label.equals("plugin " + id) || label.equals("plugin " + id + " signature")) {
                    return plugin;
                }
            }
            throw new IllegalStateException("No plugin for " + label);
        }

        @Override
        public long outputBytes() {
            return outputBytes;
        }

        @Override
        public Duration scannerTimeout() {
            return ScannerLimits.DEFAULT.timeout();
        }

        @Override
        public Optional<String> whyUnavailable() {
            return Optional.empty();
        }

        @Override
        public void exportImage(String reference, String platform, Path destination) {
            throw new UnsupportedOperationException();
        }

        @Override
        public ContainerRunner.ContainerResult run(ContainerRun request) {
            requests.add(request);
            JsonNode plugin = plugin(request.label());
            if (request.label().endsWith(" signature")) {
                JsonNode cosign = plugin.get("cosign");
                if (cosign.has("throws")) {
                    throw ScannerFailureException.of(request.label(), cosign.get("throws").asText());
                }
                return new ContainerRunner.ContainerResult("", cosign.get("stderr").asText(), cosign.get("exit").asInt());
            }
            JsonNode run = plugin.get("run");
            if (run.has("throws")) {
                throw ScannerFailureException.of(request.label(), run.get("throws").asText());
            }
            if (run.has("noOutput")) {
                return new ContainerRunner.ContainerResult("", run.get("stderr").asText(), run.get("exit").asInt());
            }
            JsonNode file = run.get("file");
            ContainerRunner.OutputFile read = switch (file.get("kind").asText()) {
                case "read" -> new ContainerRunner.OutputFile.Read(file.get("content").asText().getBytes(StandardCharsets.UTF_8));
                case "missing" -> new ContainerRunner.OutputFile.Missing();
                case "notRegular" -> new ContainerRunner.OutputFile.NotRegular();
                case "tooLarge" -> new ContainerRunner.OutputFile.TooLarge(file.get("size").asLong());
                default -> throw new IllegalArgumentException(file.get("kind").asText());
            };
            boolean full = run.get("full").asBoolean();
            return new ContainerRunner.ContainerResult("", run.get("stderr").asText(), run.get("exit").asInt(),
                    Optional.of(new ContainerRunner.CollectedOutput(request.output().bytes(), full ? 0 : 1 << 20,
                            full ? 0 : 100, read)));
        }

        @Override
        public ContainerRunner.RegistryAccess registryAccessFor(String reference) {
            for (JsonNode plugin : scenario.get("plugins")) {
                if (plugin.get("cosign").has("credentialsHeld")) {
                    return new ContainerRunner.RegistryAccess(ContainerRunner.registryOf(reference),
                            plugin.get("cosign").get("credentialsHeld").asBoolean());
                }
            }
            return new ContainerRunner.RegistryAccess(ContainerRunner.registryOf(reference), false);
        }
    }

    // ----------------------------------------------------------------------------------------------

    private static JsonNode cases(String relative) throws Exception {
        return WIRE.readTree(ReferenceSet.read(relative));
    }

    /** One answer per line: a difference reads as the case that changed. */
    static String lines(ArrayNode answers) throws Exception {
        List<String> each = new ArrayList<>();
        for (JsonNode answer : answers) {
            each.add(WIRE.writeValueAsString(answer));
        }
        return "[\n" + String.join(",\n", each) + "\n]\n";
    }
}

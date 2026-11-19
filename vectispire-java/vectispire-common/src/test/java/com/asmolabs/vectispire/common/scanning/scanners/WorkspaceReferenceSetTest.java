package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.LanguageCensus;
import com.asmolabs.vectispire.common.scanning.ProjectManifest;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Fixed trees in, what the scan learns from them in-process out — the language census, the project
 * manifest and the API discovery — for the Rust port's {@code scanners::census}, {@code scanners::manifest}
 * and {@code scanners::api_discovery} to match (see {@code ReferenceSet}).
 *
 * <p><b>These read the audited repository inside the worker's own process</b>, so the cases are mostly the
 * repository's author's choices: links out of the tree, files past the size bound, deep trees, bytes that are
 * not UTF-8, manifests that do not parse, shapes written against the patterns. Each case is a tree described
 * in {@code reference/workspace/cases/<topic>.json} — text, base64, a run of repeated text, or a link, whose
 * {@code {outside}} names a directory beside the tree holding a manifest, a specification and controllers
 * that must never be read — built afresh in a temporary directory on each side, so a tree of eight
 * megabytes costs a line in the repository.
 *
 * <p><b>Only what does not depend on the order a directory lists its entries in</b>: the endpoints are written
 * grouped by file (a stable sort, so the order inside one file is kept), the contracts by path, and no case
 * declares one endpoint in two files — which one survives the merge would be the file system's choice. The
 * answers are one JSON line per case, as the agent's mapper writes the records.
 */
class WorkspaceReferenceSetTest {

    private static final ObjectMapper WIRE = JsonMapper.builder()
            .addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
            .addModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private static final ObjectMapper CASES = new ObjectMapper();

    @Test
    void theAnswersTheRustPortIsHeldTo(@TempDir Path temporary) throws Exception {
        List<Path> topics;
        try (Stream<Path> listed = Files.list(ReferenceSet.resolve("workspace/cases"))) {
            topics = listed.filter(path -> path.toString().endsWith(".json")).sorted().toList();
        }
        int index = 0;
        for (Path topic : topics) {
            StringBuilder answers = new StringBuilder();
            for (JsonNode spec : CASES.readTree(Files.readString(topic)).path("cases")) {
                Path place = Files.createDirectory(temporary.resolve("case-" + index++));
                answers.append(WIRE.writeValueAsString(answer(spec, place))).append('\n');
            }
            String name = topic.getFileName().toString().replace(".json", ".jsonl");
            ReferenceSet.expect("workspace/answers/" + name, answers.toString());
        }
    }

    private static Map<String, Object> answer(JsonNode spec, Path place) throws Exception {
        Path outside = outside(place.resolve("outside"));
        Path tree = Files.createDirectory(place.resolve("tree"));
        for (JsonNode entry : spec.path("entries")) {
            build(tree, outside, entry);
        }
        Path root = spec.has("root") ? tree.resolve(spec.get("root").asText()) : tree;

        Map<String, Object> answer = new LinkedHashMap<>();
        answer.put("name", spec.path("name").asText());
        answer.put("census", census(LanguageCensus.of(root, Set.of())));
        if (spec.has("wanted")) {
            Set<Language> wanted = EnumSet.noneOf(Language.class);
            spec.get("wanted").forEach(name -> wanted.add(Language.fromJson(name.asText())));
            answer.put("censusWanted", census(LanguageCensus.of(root, wanted)));
        }
        answer.put("project", ProjectManifest.read(root).orElse(null));
        int ceiling = spec.path("ceiling").asInt(ApiEndpoint.MAX_PER_REPOSITORY);
        Map<String, Object> api = new LinkedHashMap<>();
        try {
            ApiDiscoveryScanner.Result result =
                    ApiDiscoveryScanner.scan(root, ApiDiscoveryScanner.DEADLINE, System::nanoTime, ceiling);
            List<ApiEndpoint> endpoints = new ArrayList<>(result.endpoints());
            endpoints.sort(Comparator.comparing(ApiEndpoint::filePath));
            List<ApiContract> contracts = new ArrayList<>(result.contracts());
            contracts.sort(Comparator.comparing(ApiContract::contractPath));
            api.put("endpoints", endpoints);
            api.put("contracts", contracts);
        } catch (RuntimeException failed) {
            // As `ScanRunner.step` records it, the temporary directory's name taken out.
            String message = failed.getMessage() == null ? failed.toString() : failed.getMessage();
            api.put("failure", message.replace(root.toString(), "{root}"));
        }
        answer.put("api", api);
        return answer;
    }

    private static Map<String, Object> census(LanguageCensus.Census census) {
        Map<String, Object> written = new LinkedHashMap<>();
        written.put("found", census.found().stream().sorted().map(Language::wireName).toList());
        written.put("complete", census.complete());
        return written;
    }

    /** One entry of a case's tree: a directory, a link, or a file of text, base64 or repeated text. */
    private static void build(Path tree, Path outside, JsonNode entry) throws Exception {
        Path path = tree.resolve(entry.get("path").asText());
        Files.createDirectories(path.getParent());
        if (entry.path("dir").asBoolean(false)) {
            Files.createDirectories(path);
        } else if (entry.has("link")) {
            Files.createSymbolicLink(path, Path.of(entry.get("link").asText().replace("{outside}", outside.toString())));
        } else if (entry.has("base64")) {
            Files.write(path, Base64.getDecoder().decode(entry.get("base64").asText()));
        } else {
            StringBuilder content = new StringBuilder(entry.path("head").asText(""));
            content.append(entry.path("text").asText("").repeat(entry.path("repeat").asInt(1)));
            content.append(entry.path("tail").asText(""));
            Files.writeString(path, content, StandardCharsets.UTF_8);
        }
    }

    /**
     * What a link may point at, beside the tree: a manifest of each kind with a version that says where it
     * came from, a specification, a controller of each language, an ingress — none of which may reach an answer.
     */
    private static Path outside(Path outside) throws Exception {
        Files.createDirectories(outside.resolve("dir"));
        Files.writeString(outside.resolve("package.json"), "{\"version\":\"host-secret\"}");
        Files.writeString(outside.resolve("pom.xml"), "<project><version>host-secret</version></project>");
        Files.writeString(outside.resolve("gradle.properties"), "version=host-secret\n");
        Files.writeString(outside.resolve("pyproject.toml"), "[project]\nversion = \"host-secret\"\n");
        Files.writeString(outside.resolve("openapi.json"),
                "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"host\"},\"paths\":{\"/host-spec\":{\"get\":{}}}}");
        Files.writeString(outside.resolve("Host.java"),
                "@RestController\nclass Host {\n  @GetMapping(\"/host-java\")\n  void get() {}\n}\n");
        Files.writeString(outside.resolve("ingress.yaml"), "kind: Ingress\nspec:\n  - path: /\n");
        Files.writeString(outside.resolve("dir/app.py"), "@app.get(\"/host-dir\")\ndef host(): pass\n");
        Files.writeString(outside.resolve("dir/Main.java"), "class Main {}\n");
        return outside;
    }
}

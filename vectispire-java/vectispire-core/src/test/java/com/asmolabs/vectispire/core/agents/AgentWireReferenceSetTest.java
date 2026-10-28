package com.asmolabs.vectispire.core.agents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.asmolabs.vectispire.common.scanning.ProjectManifest;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner.IacFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner.SastFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.agents.web.AgentJobPoller;
import com.asmolabs.vectispire.core.agents.web.AgentsController;
import com.asmolabs.vectispire.core.config.CoreConfiguration;
import com.asmolabs.vectispire.core.rules.RuleSetService;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.ScanPlugins;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.server.ResponseStatusException;

/**
 * The agent protocol as this control plane reads and writes it — {@code artifacts/java-read.json} and
 * {@code artifacts/server-wire.json}, the answers the server half of the Rust {@code protocol} crate is held to.
 *
 * <p><b>Two mappers, because the control plane has two.</b> A result and a failure report arrive as bytes (the
 * signature covers them) and are read by {@code CoreConfiguration}'s Jackson 2 bean; every other body — the hello and
 * the sealing-key announcement read, the claim, the hello and the failure answers written — goes through Spring MVC,
 * which Spring Boot 4 hands its own auto-configured Jackson 3 mapper. Both are taken from where the application takes
 * them, never rebuilt by hand here: a copy agrees with itself.
 *
 * <p><b>What a result says is decided by what the reader did with it</b> (decision 0007): a step read as absent
 * resolves nothing, read as empty resolves its backlog. So each body is recorded with what the mapper made of it, step
 * by step, or with the refusal that made the route answer 400. Texts are recorded as their UTF-8 bytes — a lone
 * surrogate as {@code ?} — which is what the fingerprint hashes and the database stores.
 *
 * <p>Bodies too large to commit are described by a generator, which the Rust test runs the same way.
 */
class AgentWireReferenceSetTest {

    private static final ObjectMapper CONTROL_PLANE = controlPlaneMapper();
    private static final tools.jackson.databind.json.JsonMapper HTTP = httpMapper();
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    @Test
    void whatTheControlPlaneReadsInAResult() throws Exception {
        ArrayNode cases = NODES.arrayNode();
        for (Map.Entry<String, byte[]> written : agentWritten().entrySet()) {
            cases.add(read(written.getKey(), body(written.getValue()), written.getValue()));
        }
        for (Map.Entry<String, String> handWritten : handWritten().entrySet()) {
            byte[] bytes = handWritten.getValue().getBytes(StandardCharsets.UTF_8);
            cases.add(read(handWritten.getKey(), body(bytes), bytes));
        }
        for (Map.Entry<String, byte[]> raw : rawBytes().entrySet()) {
            cases.add(read(raw.getKey(), body(raw.getValue()), raw.getValue()));
        }
        for (ObjectNode generator : generators()) {
            ObjectNode source = NODES.objectNode();
            source.set("generated", generator);
            cases.add(read(name(generator), source, generate(generator)));
        }
        assertThat(cases.size()).isGreaterThan(150);
        ObjectNode out = RustReference.object();
        out.set("cases", cases);
        RustReference.expect("artifacts/java-read.json", out, AgentWireReferenceSetTest.class);
    }

    @Test
    void whatTheControlPlaneWritesAndReadsAroundIt() throws Exception {
        ObjectNode out = RustReference.object();
        out.set("claims", claims());
        out.set("hello", hello());
        out.set("contract", contract());
        out.set("hello_requests", requests(helloRequests(), AgentsController.HelloRequest.class));
        out.set("sealing_key_requests", requests(sealingKeyRequests(), AgentsController.SealingKeyRequest.class));
        out.set("failure_reports", failureReports());
        out.set("failure_answers", failureAnswers());
        out.set("refusals", refusals());
        RustReference.expect("artifacts/server-wire.json", out, AgentWireReferenceSetTest.class);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Results

    /** Bodies as the Java agent writes them — its mapper is built as the control plane's. */
    private static Map<String, byte[]> agentWritten() throws Exception {
        Map<String, byte[]> cases = new LinkedHashMap<>();
        cases.put("agent-wrote-nothing-ran", CONTROL_PLANE.writeValueAsBytes(ScanArtifacts.builder().build(Duration.ZERO)));
        cases.put("agent-wrote-everything-empty", CONTROL_PLANE.writeValueAsBytes(ScanArtifacts.builder()
                .sbom(CONTROL_PLANE.readTree("{\"bomFormat\":\"CycloneDX\",\"components\":[]}"))
                .project(new ProjectManifest.Project("maven", null))
                .languages(Set.of())
                .dependencies(List.of()).secrets(List.of()).iac(List.of()).sast(List.of())
                .apiEndpoints(List.of()).apiContracts(List.of())
                .build(Duration.ofSeconds(1))));
        cases.put("agent-wrote-every-type-and-plugin-state", languagesInOrder(CONTROL_PLANE.writeValueAsBytes(ScanArtifacts.builder()
                .sbom(CONTROL_PLANE.readTree(
                        "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"jackson\",\"version\":\"2.21.0\"}]}"))
                .project(new ProjectManifest.Project("npm", "1.4.0"))
                .languages(EnumSet.of(Language.JAVASCRIPT, Language.TYPESCRIPT))
                .dependencies(List.of(new DependencyFinding("CVE-2026-0001", Severity.HIGH, "left-pad", "1.0.0", "1.0.1",
                        "Ünïcode — \"quoted\"\n", "https://example.invalid/CVE-2026-0001", "pkg:npm/left-pad@1.0.0")))
                .secrets(List.of(new SecretFinding("aws-access-token", "AWS key", "src/a.yaml", 12, "src/a.yaml:aws-access-token:12")))
                .iac(List.of(new IacFinding("CKV_AWS_20", "S3 public", "main.tf", 3, null, "aws_s3_bucket.a")))
                .sast(List.of(new SastFinding("java.sqli", "security", Severity.CRITICAL, "HIGH", "A.java", 40, "SQL", "A03")))
                .apiEndpoints(List.of(new ApiEndpoint("get", "users/{id}", true, "bearer", ApiVisibility.PUBLIC,
                        "Users.java", 7, "spring", "getUser", null, "users")))
                .apiContracts(List.of(new ApiContract("openapi.yaml", "openapi-3", "Users", "1.0", 2, List.of("/users", "/users/{id}"))))
                .plugin(new PluginStep.Produced("p1", "a".repeat(64), "tool", "1.0",
                        List.of(new SarifFinding("R1", Severity.MEDIUM, "a.c", 3, "m"), new SarifFinding("R2", Severity.LOW, null, null, null)),
                        PluginStep.Signature.VERIFIED))
                .plugin(new PluginStep.Produced("p2", "b".repeat(64), null, null, List.of(), null))
                .plugin(new PluginStep.NotApplicable("p3", "c".repeat(64), EnumSet.of(Language.PYTHON, Language.GO)))
                .plugin(new PluginStep.Absent("p4", "d".repeat(64), "pull failed"))
                .plugin(new PluginStep.Refused("p5", "e".repeat(64), PluginStep.Refusal.SIGNATURE_UNVERIFIED, "no signature"))
                .failed("sast", "semgrep: timed out after PT10M")
                .build(Duration.ofMillis(3_723_500)))));
        return cases;
    }

    /**
     * The agent's {@code languages} sorted by name. {@code ScanArtifacts} holds them in {@code toUnmodifiableSet()},
     * whose iteration order the JVM draws at start-up ({@code ImmutableCollections.SALT}): written as it is, the body
     * of a set of two came out in either order, one run in two, and the case failed or passed with it — alone and
     * among the other reference tests alike. Any order is the same set to the reader; the file pins one.
     */
    private static byte[] languagesInOrder(byte[] body) throws Exception {
        ObjectNode tree = (ObjectNode) CONTROL_PLANE.readTree(body);
        if (tree.get("languages") instanceof ArrayNode languages) {
            List<String> names = new ArrayList<>();
            languages.forEach(name -> names.add(name.asText()));
            names.sort(null);
            languages.removeAll();
            names.forEach(languages::add);
        }
        return CONTROL_PLANE.writeValueAsBytes(tree);
    }

    private static final String D64 = "d".repeat(64);

    /** Bodies an agent could send and Jackson reads in a way worth pinning — leniencies first, refusals after. */
    private static Map<String, String> handWritten() {
        Map<String, String> cases = new LinkedHashMap<>();
        // Shapes.
        cases.put("empty-object", "{}");
        // One step present each: any one of the four analyses is an observation.
        cases.put("only-dependencies", "{\"dependencies\":[]}");
        cases.put("only-secrets", "{\"secrets\":[]}");
        cases.put("only-iac", "{\"iac\":[]}");
        cases.put("only-sast", "{\"sast\":[]}");
        cases.put("only-api-endpoints", "{\"apiEndpoints\":[]}");
        cases.put("every-field-null", "{\"sbom\":null,\"project\":null,\"languages\":null,\"dependencies\":null,\"secrets\":null,"
                + "\"iac\":null,\"sast\":null,\"apiEndpoints\":null,\"apiContracts\":null,\"plugins\":null,\"failures\":null,\"duration\":null}");
        cases.put("unknown-fields-passed-over", "{\"aFieldFromTheFuture\":{\"nested\":[1,{\"a\":null}],\"x\":1e400},"
                + "\"secrets\":[{\"rule\":\"r\",\"line\":3,\"extra\":[1,2],\"file\":\"f\"}],"
                + "\"plugins\":[{\"state\":\"absent\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"reason\":\"r\",\"later\":true}],"
                + "\"failures\":[{\"step\":\"s\",\"reason\":\"r\",\"code\":7}],\"project\":{\"type\":\"npm\",\"version\":\"1\",\"lockfile\":\"x\"},"
                + "\"duration\":\"PT1S\"}");
        cases.put("field-names-are-case-sensitive", "{\"Secrets\":[],\"SECRETS\":[],\"api_endpoints\":[]}");
        cases.put("escaped-field-name", "{\"secr\\u0065ts\":[]}");
        cases.put("sbom-text", "{\"sbom\":\"not a document\"}");
        cases.put("sbom-array", "{\"sbom\":[1,2]}");
        cases.put("sbom-number", "{\"sbom\":0}");
        cases.put("sbom-false", "{\"sbom\":false}");
        cases.put("sbom-with-nulls", "{\"sbom\":{\"a\":null,\"b\":[null],\"c\":{}}}");
        cases.put("sbom-duplicate-keys-inside", "{\"sbom\":{\"a\":1,\"a\":2}}");
        // Duplicates.
        cases.put("duplicate-step-later-null-wins", "{\"secrets\":[],\"secrets\":null}");
        cases.put("duplicate-step-later-list-wins", "{\"secrets\":null,\"secrets\":[{\"rule\":\"r\"}]}");
        cases.put("duplicate-sbom-later-null-wins", "{\"sbom\":{\"a\":1},\"sbom\":null}");
        cases.put("duplicate-field-in-a-finding", "{\"secrets\":[{\"line\":1,\"line\":2,\"rule\":\"a\",\"rule\":\"b\"}]}");
        cases.put("duplicate-plugin-state", "{\"plugins\":[{\"state\":\"absent\",\"state\":\"refused\",\"pluginId\":\"p\",\"manifestDigest\":\"d\"}]}");
        // Escapes and surrogates, in a text that enters a fingerprint.
        for (Map.Entry<String, String> text : Map.ofEntries(
                Map.entry("lone-high-surrogate", "a\\uD800b"),
                Map.entry("lone-low-surrogate", "a\\uDC00b"),
                Map.entry("lone-high-at-the-end", "a\\uD800"),
                Map.entry("lone-high-at-the-start", "\\uD800a"),
                Map.entry("high-then-pair", "\\uD800\\uD800\\uDC00"),
                Map.entry("reversed-pair", "\\uDC00\\uD800"),
                Map.entry("valid-pair", "\\uD83D\\uDE00"),
                Map.entry("valid-pair-lower-case", "\\ud83d\\ude00"),
                Map.entry("lone-high-lower-case", "\\ud800"),
                Map.entry("high-then-escaped-newline", "\\uD800\\n"),
                Map.entry("high-then-raw-pair-half", "\\uD800\u00e9"),
                Map.entry("escaped-backslash-then-u", "\\\\uD800"),
                Map.entry("escaped-backslash-then-surrogate", "\\\\\\uD800"),
                Map.entry("escaped-quote-then-surrogate", "\\\"\\uD800\\\""),
                Map.entry("every-simple-escape", "\\\"\\\\\\/\\b\\f\\n\\r\\t"),
                Map.entry("nul-escape", "a\\u0000b"),
                Map.entry("raw-astral", "\uD83D\uDE00")).entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
            cases.put("text-" + text.getKey(), "{\"secrets\":[{\"rule\":\"r\",\"description\":\"" + text.getValue() + "\"}]}");
        }
        cases.put("surrogate-in-a-field-name", "{\"secr\\uD800ets\":[]}");
        cases.put("name-lone-low-surrogate", "{\"x\\uDC00\":1,\"secrets\":[]}");
        cases.put("name-high-then-other-escape", "{\"x\\uD800\\u0041\":1,\"secrets\":[]}");
        cases.put("name-high-at-the-end", "{\"x\\uD800\":1,\"secrets\":[]}");
        cases.put("name-valid-pair", "{\"\\uD83D\\uDE00\":1,\"secrets\":[]}");
        cases.put("name-reversed-pair-then-low", "{\"\\uDC00\\uD800\\uDC00\":1,\"secrets\":[]}");
        cases.put("name-high-high-low", "{\"\\uD800\\uD800\\uDC00\":1,\"secrets\":[]}");
        cases.put("name-known-field-with-low-surrogate", "{\"secrets\\uDC00\":[]}");
        cases.put("name-empty", "{\"\":1,\"secrets\":[]}");
        cases.put("surrogate-in-the-sbom", "{\"sbom\":{\"name\":\"\\uD800\"}}");
        cases.put("surrogate-in-an-unknown-field", "{\"later\":\"\\uDFFF\",\"secrets\":[]}");
        cases.put("surrogate-in-a-language", "{\"languages\":[\"j\\uD800\"]}");
        // Trailing content and roots.
        cases.put("trailing-garbage", "{\"secrets\":[]} xyz");
        cases.put("two-documents", "{}{\"secrets\":[]}");
        cases.put("trailing-whitespace", "{\"secrets\":[]}\n\t \r");
        cases.put("trailing-unclosed", "{} {");
        cases.put("leading-whitespace", " \n\t{\"secrets\":[]}");
        cases.put("empty-body", "");
        cases.put("whitespace-only", "  \n");
        cases.put("null-literal", "null");
        cases.put("array-root", "[]");
        cases.put("string-root", "\"x\"");
        cases.put("number-root", "1");
        cases.put("true-root", "true");
        // Syntax Jackson's defaults refuse.
        cases.put("comment", "{/* c */\"secrets\":[]}");
        cases.put("line-comment", "{\"secrets\":[]// c\n}");
        cases.put("single-quotes", "{'secrets':[]}");
        cases.put("unquoted-name", "{secrets:[]}");
        cases.put("trailing-comma-object", "{\"secrets\":[],}");
        cases.put("trailing-comma-array", "{\"languages\":[\"java\",]}");
        cases.put("nan", "{\"later\":NaN}");
        cases.put("leading-zero", "{\"later\":01}");
        cases.put("plus-sign", "{\"later\":+1}");
        cases.put("unterminated", "{\"secrets\":[");
        cases.put("raw-tab-in-text", "{\"later\":\"a\tb\"}");
        cases.put("raw-newline-in-text", "{\"later\":\"a\nb\"}");
        cases.put("unknown-escape", "{\"later\":\"\\q\"}");
        cases.put("short-unicode-escape", "{\"later\":\"\\u12\"}");
        cases.put("non-hex-unicode-escape", "{\"later\":\"\\u12G4\"}");
        cases.put("huge-exponent-skipped", "{\"later\":1e99999}");
        cases.put("missing-colon", "{\"secrets\" []}");
        cases.put("missing-value", "{\"secrets\":}");
        cases.put("bare-word", "{\"later\":nul}");
        // Integers: a finding's line.
        for (Map.Entry<String, String> line : List.of(
                Map.entry("integer", "12"), Map.entry("negative", "-3"), Map.entry("text", "\"12\""),
                Map.entry("text-padded", "\" 12 \""), Map.entry("text-empty", "\"\""), Map.entry("text-blank", "\" \""),
                Map.entry("text-word", "\"abc\""), Map.entry("text-decimal", "\"12.5\""), Map.entry("text-hex", "\"0x10\""),
                Map.entry("text-plus", "\"+5\""), Map.entry("decimal", "12.9"), Map.entry("negative-decimal", "-12.9"),
                Map.entry("exponent", "1e1"), Map.entry("big-exponent", "1.5e9"), Map.entry("out-of-range-exponent", "3e9"),
                Map.entry("null", "null"), Map.entry("true", "true"), Map.entry("false", "false"),
                Map.entry("max", "2147483647"), Map.entry("min", "-2147483648"), Map.entry("too-big", "2147483648"),
                Map.entry("too-small", "-2147483649"), Map.entry("long", "9223372036854775808"), Map.entry("object", "{}"),
                Map.entry("array", "[]"), Map.entry("array-of-one", "[3]"), Map.entry("minus-zero", "-0"),
                Map.entry("decimal-zero", "0.0"),
                Map.entry("tiny", "1e-400"), Map.entry("text-null", "\"null\""), Map.entry("text-leading-zeros", "\"007\""),
                Map.entry("text-minus-zero", "\"-0\""), Map.entry("text-arabic-digits", "\"\u0661\u0662\""),
                Map.entry("text-padded-negative", "\" -3 \""), Map.entry("text-trailing-letter", "\"12a\""),
                Map.entry("text-long-digits", "\"0000000000012\""), Map.entry("text-too-big", "\"2147483648\""),
                Map.entry("text-plus-only", "\"+\""), Map.entry("text-nbsp", "\"\u00a012\""),
                Map.entry("half", "0.5"), Map.entry("just-over-max", "2147483647.5"), Map.entry("just-under-min", "-2147483648.9"))) {
            cases.put("line-" + line.getKey(), "{\"secrets\":[{\"rule\":\"r\",\"line\":" + line.getValue() + "}]}");
            cases.put("boxed-line-" + line.getKey(), "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"d\","
                    + "\"findings\":[{\"ruleId\":\"r\",\"line\":" + line.getValue() + "}]}]}");
        }
        cases.put("count-text", "{\"apiContracts\":[{\"contractPath\":\"a\",\"endpointsCount\":\"3\"}]}");
        // Texts: a finding's rule.
        for (Map.Entry<String, String> text : List.of(
                Map.entry("integer", "12"), Map.entry("decimal", "1.50"), Map.entry("minus-zero", "-0"),
                Map.entry("exponent", "1E+2"), Map.entry("big", "123456789012345678901234567890"), Map.entry("true", "true"),
                Map.entry("false", "false"), Map.entry("object", "{}"), Map.entry("array", "[]"),
                Map.entry("array-of-one", "[\"a\"]"), Map.entry("empty", "\"\""), Map.entry("huge-exponent", "1e99999"),
                Map.entry("null", "null"))) {
            cases.put("rule-" + text.getKey(), "{\"secrets\":[{\"rule\":" + text.getValue() + "}]}");
        }
        // Booleans: an endpoint's authRequired.
        for (Map.Entry<String, String> flag : List.of(
                Map.entry("true", "true"), Map.entry("text-true", "\"true\""), Map.entry("text-upper", "\"TRUE\""),
                Map.entry("text-false", "\"false\""), Map.entry("one", "1"), Map.entry("zero", "0"), Map.entry("two", "2"),
                Map.entry("decimal", "1.0"), Map.entry("null", "null"), Map.entry("text-empty", "\"\""),
                Map.entry("text-yes", "\"yes\""), Map.entry("object", "{}"), Map.entry("text-padded", "\" true\""),
                Map.entry("text-title", "\"True\""), Map.entry("text-odd-case", "\"tRUE\""), Map.entry("text-title-false", "\"False\""),
                Map.entry("text-upper-false", "\"FALSE\""), Map.entry("text-null", "\"null\""), Map.entry("text-blank", "\" \""),
                Map.entry("minus-zero", "-0"), Map.entry("exponent", "1e0"), Map.entry("big", "99999999999999999999"),
                Map.entry("text-one", "\"1\""), Map.entry("array", "[]"))) {
            cases.put("auth-" + flag.getKey(), "{\"apiEndpoints\":[{\"method\":\"get\",\"path\":\"/a\",\"authRequired\":" + flag.getValue() + "}]}");
        }
        // Enums: a dependency's severity (by name), an endpoint's visibility, a plugin's signature and refusal (by wire name).
        for (Map.Entry<String, String> severity : List.of(
                Map.entry("name", "\"HIGH\""), Map.entry("lower", "\"high\""), Map.entry("mixed", "\"High\""),
                Map.entry("padded", "\" HIGH\""), Map.entry("index", "1"), Map.entry("index-text", "\"1\""),
                Map.entry("index-out-of-range", "6"), Map.entry("negative-index", "-1"), Map.entry("decimal", "1.0"),
                Map.entry("empty", "\"\""), Map.entry("null", "null"), Map.entry("unknown", "\"SEVERE\""),
                Map.entry("true", "true"), Map.entry("object", "{}"), Map.entry("blank", "\" \""),
                Map.entry("index-leading-zero", "\"01\""), Map.entry("index-padded", "\" 1\""), Map.entry("index-plus", "\"+1\""),
                Map.entry("name-trailing-space", "\"HIGH \""), Map.entry("name-tab", "\"\\tHIGH\""), Map.entry("name-nbsp", "\"\u00a0HIGH\""),
                Map.entry("unknown-name", "\"UNKNOWN\""), Map.entry("index-zero", "0"), Map.entry("index-zero-text", "\"0\""),
                Map.entry("index-big", "99999999999"), Map.entry("index-text-big", "\"99999999999\""), Map.entry("text-null", "\"null\""),
                Map.entry("array", "[\"HIGH\"]"))) {
            cases.put("severity-" + severity.getKey(), "{\"dependencies\":[{\"identifier\":\"CVE-1\",\"severity\":" + severity.getValue() + "}]}");
        }
        cases.put("visibility-name", "{\"apiEndpoints\":[{\"path\":\"/a\",\"visibility\":\"INTERNAL\"}]}");
        cases.put("visibility-lower", "{\"apiEndpoints\":[{\"path\":\"/a\",\"visibility\":\"internal\"}]}");
        cases.put("visibility-null", "{\"apiEndpoints\":[{\"path\":\"/a\",\"visibility\":null}]}");
        cases.put("sarif-severity-name", "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"findings\":[{\"severity\":\"LOW\"}]}]}");
        cases.put("sarif-severity-lower", "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"findings\":[{\"severity\":\"low\"}]}]}");
        for (Map.Entry<String, String> signature : List.of(
                Map.entry("verified", "\"verified\""), Map.entry("not-required", "\"not_required\""),
                Map.entry("upper", "\"VERIFIED\""), Map.entry("unknown", "\"vouched\""), Map.entry("null", "null"),
                Map.entry("number", "1"), Map.entry("padded", "\" waived\""), Map.entry("object", "{}"),
                Map.entry("true", "true"), Map.entry("array", "[]"), Map.entry("empty", "\"\""))) {
            cases.put("signature-" + signature.getKey(), "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"d\","
                    + "\"findings\":[],\"signature\":" + signature.getValue() + "}]}");
        }
        cases.put("refusal-known", "{\"plugins\":[{\"state\":\"refused\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"refusal\":\"unsigned\",\"reason\":\"r\"}]}");
        cases.put("refusal-unknown", "{\"plugins\":[{\"state\":\"refused\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"refusal\":\"later\",\"reason\":\"r\"}]}");
        // Lists.
        cases.put("step-as-object", "{\"secrets\":{}}");
        cases.put("step-as-text", "{\"secrets\":\"none\"}");
        cases.put("step-as-empty-text", "{\"secrets\":\"\"}");
        cases.put("step-as-number", "{\"secrets\":0}");
        cases.put("finding-as-number", "{\"secrets\":[1]}");
        cases.put("finding-as-text", "{\"secrets\":[\"a\"]}");
        cases.put("finding-as-array", "{\"secrets\":[[]]}");
        cases.put("finding-null", "{\"secrets\":[null,{\"rule\":\"r\"}]}");
        cases.put("dependency-null", "{\"dependencies\":[null]}");
        cases.put("failure-null", "{\"failures\":[null]}");
        cases.put("failure-as-text", "{\"failures\":[\"x\"]}");
        cases.put("failure-step-number", "{\"failures\":[{\"step\":1,\"reason\":true}]}");
        cases.put("failures-as-object", "{\"failures\":{}}");
        cases.put("plugins-null-element", "{\"plugins\":[null,{\"state\":\"absent\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"reason\":\"r\"}]}");
        cases.put("plugins-as-object", "{\"plugins\":{}}");
        cases.put("languages-null-element", "{\"languages\":[null,\"java\"]}");
        cases.put("languages-not-normalised", "{\"languages\":[\"Java\",\"java\",\" java\",\"java\"]}");
        cases.put("languages-scalars", "{\"languages\":[1,true,1.5]}");
        cases.put("languages-as-text", "{\"languages\":\"java\"}");
        cases.put("languages-empty", "{\"languages\":[]}");
        cases.put("languages-nested", "{\"languages\":[[\"java\"]]}");
        cases.put("project-as-text", "{\"project\":\"maven\"}");
        cases.put("project-as-array", "{\"project\":[]}");
        cases.put("project-empty", "{\"project\":{}}");
        cases.put("project-type-number", "{\"project\":{\"type\":7}}");
        cases.put("contract-paths-null", "{\"apiContracts\":[{\"contractPath\":\"a\",\"declaredPaths\":null}]}");
        cases.put("contract-paths-null-element", "{\"apiContracts\":[{\"contractPath\":\"a\",\"declaredPaths\":[\"/a\",null]}]}");
        cases.put("contract-paths-as-text", "{\"apiContracts\":[{\"contractPath\":\"a\",\"declaredPaths\":\"/a\"}]}");
        // An endpoint's normalisation, in its record.
        for (Map.Entry<String, String> endpoint : List.of(
                Map.entry("method-lower", "\"method\":\"get\",\"path\":\"/a\""),
                Map.entry("method-unicode", "\"method\":\"\u00df\u01c6\u0131i\",\"path\":\"/a\""),
                Map.entry("method-null", "\"path\":\"/a\""),
                Map.entry("path-relative", "\"method\":\"GET\",\"path\":\"a/b\""),
                Map.entry("path-empty", "\"method\":\"GET\",\"path\":\"\""),
                Map.entry("path-blank", "\"method\":\"GET\",\"path\":\" \\t\""),
                Map.entry("path-nbsp", "\"method\":\"GET\",\"path\":\"\u00a0\""),
                Map.entry("path-null", "\"method\":\"GET\""),
                Map.entry("everything", "\"method\":\"post\",\"path\":\"/u\",\"authRequired\":true,\"authType\":\"basic\","
                        + "\"visibility\":\"PUBLIC\",\"filePath\":\"U.java\",\"lineNumber\":9,\"framework\":\"spring\","
                        + "\"operationId\":\"o\",\"summary\":\"s\",\"tags\":\"t\""))) {
            cases.put("endpoint-" + endpoint.getKey(), "{\"apiEndpoints\":[{" + endpoint.getValue() + "}]}");
        }
        // Plugin steps.
        cases.put("plugin-state-missing", "{\"plugins\":[{\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"reason\":\"r\"}]}");
        cases.put("plugin-state-unknown", "{\"plugins\":[{\"state\":\"skipped\",\"pluginId\":\"p\",\"manifestDigest\":\"d\"}]}");
        cases.put("plugin-state-upper", "{\"plugins\":[{\"state\":\"Produced\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"findings\":[]}]}");
        cases.put("plugin-state-null", "{\"plugins\":[{\"state\":null,\"pluginId\":\"p\",\"manifestDigest\":\"d\"}]}");
        cases.put("plugin-state-number", "{\"plugins\":[{\"state\":1,\"pluginId\":\"p\",\"manifestDigest\":\"d\"}]}");
        cases.put("plugin-state-last", "{\"plugins\":[{\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"findings\":[],\"state\":\"produced\"}]}");
        cases.put("plugin-as-text", "{\"plugins\":[\"produced\"]}");
        cases.put("plugin-as-array", "{\"plugins\":[[\"produced\",{}]]}");
        // Jackson falls back to the wrapper-array form of a type id when an element is an array.
        cases.put("plugin-wrapped-absent", "{\"plugins\":[[\"absent\",{\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"reason\":\"r\"}]]}");
        cases.put("plugin-wrapped-null-value", "{\"plugins\":[[\"absent\",null]]}");
        cases.put("plugin-wrapped-extra-element", "{\"plugins\":[[\"absent\",{},1]]}");
        cases.put("plugin-wrapped-without-value", "{\"plugins\":[[\"absent\"]]}");
        cases.put("plugin-wrapped-number-id", "{\"plugins\":[[1,{}]]}");
        cases.put("plugin-wrapped-empty", "{\"plugins\":[[]]}");
        cases.put("plugin-wrapped-state-inside", "{\"plugins\":[[\"absent\",{\"state\":\"refused\",\"reason\":\"r\"}]]}");
        cases.put("plugin-wrapped-text-value", "{\"plugins\":[[\"absent\",\"x\"]]}");
        cases.put("plugin-wrapped-unknown-id", "{\"plugins\":[[\"skipped\",{}]]}");
        cases.put("plugin-wrapped-produced-with-findings", "{\"plugins\":[[\"produced\",{\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"findings\":[{\"ruleId\":\"r\"}]}]]}");
        cases.put("produced-findings-null", "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"" + D64 + "\",\"findings\":null}]}");
        cases.put("produced-findings-missing", "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"" + D64 + "\"}]}");
        cases.put("produced-findings-empty", "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"" + D64 + "\",\"findings\":[]}]}");
        cases.put("produced-finding-null", "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"findings\":[null]}]}");
        cases.put("produced-ids-missing", "{\"plugins\":[{\"state\":\"produced\",\"findings\":[]}]}");
        cases.put("not-applicable-languages-normalised", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\","
                + "\"languages\":[\"Python \",\"GO\",\"python\"]}]}");
        cases.put("not-applicable-language-unknown", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":[\"cobol\"]}]}");
        cases.put("not-applicable-language-null", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":[null]}]}");
        cases.put("not-applicable-language-blank", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":[\" \"]}]}");
        cases.put("not-applicable-language-number", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":[1]}]}");
        cases.put("not-applicable-languages-null", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":null}]}");
        cases.put("not-applicable-languages-missing", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\"}]}");
        cases.put("not-applicable-languages-as-text", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":\"go\"}]}");
        cases.put("not-applicable-language-dotted-i", "{\"plugins\":[{\"state\":\"not_applicable\",\"pluginId\":\"p\",\"manifestDigest\":\"d\",\"languages\":[\"PYTHON\",\"KOTL\u0130N\"]}]}");
        // Durations.
        for (Map.Entry<String, String> duration : List.of(
                Map.entry("iso", "\"PT12.345S\""), Map.entry("integer", "12"), Map.entry("decimal", "12.5"),
                Map.entry("negative", "-3"), Map.entry("negative-decimal", "-1.25"), Map.entry("days", "\"P1DT1H\""),
                Map.entry("lower-case", "\"pt1m\""), Map.entry("negative-iso", "\"-PT1S\""), Map.entry("comma", "\"PT1,5S\""),
                Map.entry("negative-parts", "\"PT-1H30M\""), Map.entry("padded", "\" PT1S \""), Map.entry("empty", "\"\""),
                Map.entry("blank", "\" \""), Map.entry("null", "null"), Map.entry("garbage", "\"garbage\""),
                Map.entry("integer-text", "\"12\""), Map.entry("decimal-text", "\"12.5\""),
                Map.entry("ten-fraction-digits", "\"PT0.0000000001S\""), Map.entry("nine-fraction-digits", "\"PT0.123456789S\""),
                Map.entry("exponent", "1e2"), Map.entry("true", "true"), Map.entry("object", "{}"), Map.entry("array", "[]"),
                Map.entry("long-overflow", "9223372036854775808"), Map.entry("max-seconds", "9223372036854775807"),
                Map.entry("weeks", "\"P1W\""), Map.entry("years", "\"P1Y\""), Map.entry("bare-p", "\"P\""),
                Map.entry("bare-pt", "\"PT\""), Map.entry("plus-iso", "\"+PT1S\""), Map.entry("minus-seconds-fraction", "\"PT-0.5S\""),
                Map.entry("hours-overflow", "\"PT9223372036854775807H\""), Map.entry("tiny-decimal", "0.0000000001"),
                Map.entry("many-decimals", "1.1234567891"), Map.entry("huge-decimal", "1e30"), Map.entry("huge-negative-decimal", "-1e30"),
                Map.entry("large-decimal", "9.5e18"), Map.entry("negative-half", "-0.5"), Map.entry("negative-many-decimals", "-1.1234567891"),
                Map.entry("past-long-decimal", "1e19"), Map.entry("one-nano", "1.0e-9"), Map.entry("under-two-nanos", "0.0000000019"),
                Map.entry("dot-without-fraction", "\"PT1.S\""), Map.entry("negative-days", "\"P-1D\""), Map.entry("negated-days", "\"-P1D\""),
                Map.entry("mixed-signs", "\"PT1H-30M\""), Map.entry("days-then-bare-t", "\"P1DT\""), Map.entry("lower-s", "\"PT0.5s\""),
                Map.entry("inner-space", "\"PT 1S\""), Map.entry("lower-everything", "\"pt1h2m3.25s\""),
                Map.entry("negated-negative", "\"-PT-1S\""), Map.entry("negative-fraction-only", "\"PT-0.000000001S\""),
                Map.entry("min-seconds", "-9223372036854775808"), Map.entry("negated-min", "\"-PT-9223372036854775808S\""),
                Map.entry("plus-signs-inside", "\"PT+1H+2S\""), Map.entry("text-nbsp", "\"\u00a0PT1S\""))) {
            cases.put("duration-" + duration.getKey(), "{\"duration\":" + duration.getValue() + "}");
        }
        return cases;
    }

    /** Bodies that are not UTF-8 text, or not only. */
    private static Map<String, byte[]> rawBytes() {
        Map<String, byte[]> cases = new LinkedHashMap<>();
        cases.put("raw-encoded-high-surrogate", secretDescription(new byte[] {'a', (byte) 0xED, (byte) 0xA0, (byte) 0x80, 'b'}));
        cases.put("raw-encoded-low-surrogate", secretDescription(new byte[] {(byte) 0xED, (byte) 0xB0, (byte) 0x80}));
        cases.put("raw-cesu-pair", secretDescription(new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0xBD, (byte) 0xED, (byte) 0xB8, (byte) 0x80}));
        cases.put("raw-invalid-byte", secretDescription(new byte[] {'a', (byte) 0xFF, 'b'}));
        cases.put("raw-continuation-byte-alone", secretDescription(new byte[] {'a', (byte) 0x80, 'b'}));
        cases.put("raw-overlong-slash", secretDescription(new byte[] {(byte) 0xC0, (byte) 0xAF}));
        cases.put("raw-overlong-three-bytes", secretDescription(new byte[] {(byte) 0xE0, (byte) 0x80, (byte) 0xAF}));
        cases.put("raw-truncated-sequence", secretDescription(new byte[] {'a', (byte) 0xE2, (byte) 0x82}));
        cases.put("raw-beyond-unicode", secretDescription(new byte[] {(byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80}));
        cases.put("raw-five-byte-form", secretDescription(new byte[] {(byte) 0xF8, (byte) 0x88, (byte) 0x80, (byte) 0x80, (byte) 0x80}));
        cases.put("raw-invalid-byte-in-unknown-field", concat("{\"later\":\"a".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xFF}, "\",\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-invalid-byte-outside-text", concat("{\"secrets\":[]".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xFF}, "}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-overlong-four-bytes-zero", secretDescription(new byte[] {(byte) 0xF0, (byte) 0x80, (byte) 0x80, (byte) 0x80}));
        cases.put("raw-largest-four-bytes", secretDescription(new byte[] {(byte) 0xF7, (byte) 0xBF, (byte) 0xBF, (byte) 0xBF}));
        cases.put("raw-overlong-quote", secretDescription(new byte[] {'a', (byte) 0xC0, (byte) 0xA2, 'b'}));
        cases.put("raw-overlong-quote-three-bytes", secretDescription(new byte[] {'a', (byte) 0xE0, (byte) 0x80, (byte) 0xA2, 'b'}));
        cases.put("raw-overlong-backslash", secretDescription(new byte[] {'a', (byte) 0xC1, (byte) 0x9C, 'n'}));
        cases.put("raw-overlong-nul", secretDescription(new byte[] {'a', (byte) 0xC0, (byte) 0x80, 'b'}));
        cases.put("raw-bad-middle-byte", secretDescription(new byte[] {(byte) 0xC2, 'A'}));
        cases.put("raw-escaped-high-then-beyond-unicode", secretDescription(concat("\\uD800".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80})));
        cases.put("raw-encoded-surrogate-in-unknown-field", concat("{\"later\":\"".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0x80}, "\",\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-overlong-in-unknown-field", concat("{\"later\":\"".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xC0, (byte) 0xA2}, "\",\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-bad-middle-in-unknown-field", concat("{\"later\":\"".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xE2, 'A', 'A'}, "\",\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-overlong-in-the-sbom", concat("{\"sbom\":{\"n\":\"".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xC0, (byte) 0xA2, (byte) 0xC1, (byte) 0x9C}, "\"}}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-encoded-surrogate-in-a-name", concat("{\"x".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0x80}, "\":1,\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-overlong-in-a-name", concat("{\"secrets".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xC0, (byte) 0xA2}, "\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-overlong-letter-in-a-name", concat("{\"secret".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xC1, (byte) 0xB3}, "\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-invalid-byte-in-a-name", concat("{\"x".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xFF}, "\":1,\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-beyond-unicode-in-a-name", concat("{\"x".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80}, "\":1,\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-invalid-bytes-after-the-document", concat("{\"secrets\":[]}".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xFF, (byte) 0xFE, 0}));
        cases.put("utf16-le-lone-surrogate", concat(new byte[] {(byte) 0xFF, (byte) 0xFE},
                "{\"secrets\":[{\"description\":\"".getBytes(StandardCharsets.UTF_16LE), new byte[] {0x00, (byte) 0xD8},
                "\"}]}".getBytes(StandardCharsets.UTF_16LE)));
        cases.put("utf16-le-without-mark", "{\"secrets\":[]}".getBytes(StandardCharsets.UTF_16LE));
        cases.put("utf16-be-with-mark", concat(new byte[] {(byte) 0xFE, (byte) 0xFF}, "{\"secrets\":[]}".getBytes(StandardCharsets.UTF_16BE)));
        cases.put("utf32-be-with-mark", concat(new byte[] {0, 0, (byte) 0xFE, (byte) 0xFF},
                "{\"secrets\":[]}".getBytes(java.nio.charset.Charset.forName("UTF-32BE"))));
        cases.put("utf32-le-with-mark", concat(new byte[] {(byte) 0xFF, (byte) 0xFE, 0, 0},
                "{\"secrets\":[]}".getBytes(java.nio.charset.Charset.forName("UTF-32LE"))));
        cases.put("utf32-beyond-unicode", concat(new byte[] {0, 0, (byte) 0xFE, (byte) 0xFF},
                "{\"secrets\":[{\"description\":\"".getBytes(java.nio.charset.Charset.forName("UTF-32BE")), new byte[] {0, 0x11, 0, 0},
                "\"}]}".getBytes(java.nio.charset.Charset.forName("UTF-32BE"))));
        cases.put("utf32-unusual-order", new byte[] {0, 0, (byte) 0xFF, (byte) 0xFE, '{', '}'});
        cases.put("utf32-le-without-mark", "{\"secrets\":[]}".getBytes(java.nio.charset.Charset.forName("UTF-32LE")));
        cases.put("utf16-be-astral", concat(new byte[] {(byte) 0xFE, (byte) 0xFF},
                "{\"secrets\":[{\"description\":\"\uD83D\uDE00\u00e9\"}]}".getBytes(StandardCharsets.UTF_16BE)));
        cases.put("raw-five-byte-lead-short", secretDescription(new byte[] {(byte) 0xF8, (byte) 0x80, (byte) 0x80, (byte) 0x80}));
        cases.put("raw-tab-beside-a-lone-surrogate", secretDescription("\\uD800\t".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-character-after-a-high-escape-in-a-name", concat("{\"x\\uD800".getBytes(StandardCharsets.UTF_8),
                new byte[] {(byte) 0xC3, (byte) 0xA9}, "\":1,\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("raw-nul-in-text", secretDescription(new byte[] {'a', 0, 'b'}));
        cases.put("raw-del-in-text", secretDescription(new byte[] {'a', 0x7F, 'b'}));
        cases.put("utf8-byte-order-mark", concat(new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF},
                "{\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("utf8-byte-order-mark-twice", concat(new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, (byte) 0xEF, (byte) 0xBB, (byte) 0xBF},
                "{\"secrets\":[]}".getBytes(StandardCharsets.UTF_8)));
        cases.put("utf16-le-with-mark", concat(new byte[] {(byte) 0xFF, (byte) 0xFE},
                "{\"secrets\":[]}".getBytes(StandardCharsets.UTF_16LE)));
        cases.put("utf16-be-without-mark", "{\"secrets\":[]}".getBytes(StandardCharsets.UTF_16BE));
        cases.put("utf32-be-without-mark", "{\"secrets\":[]}".getBytes(java.nio.charset.Charset.forName("UTF-32BE")));
        cases.put("latin1-text", secretDescription(new byte[] {'c', 'a', 'f', (byte) 0xE9}));
        return cases;
    }

    private static byte[] secretDescription(byte[] text) {
        return concat("{\"secrets\":[{\"rule\":\"r\",\"description\":\"".getBytes(StandardCharsets.UTF_8), text,
                "\"}]}".getBytes(StandardCharsets.UTF_8));
    }

    /** Jackson's stream limits — `StreamReadConstraints`' defaults — each side of the line. */
    private static List<ObjectNode> generators() {
        List<ObjectNode> generators = new ArrayList<>();
        for (int arrays : new int[] {127, 128, 129, 999, 1000}) {
            generators.add(NODES.objectNode().put("kind", "nested-unknown").put("count", arrays));
        }
        for (int objects : new int[] {200, 999, 1000}) {
            generators.add(NODES.objectNode().put("kind", "nested-sbom").put("count", objects));
        }
        generators.add(NODES.objectNode().put("kind", "nested-finding-field").put("count", 997));
        generators.add(NODES.objectNode().put("kind", "nested-finding-field").put("count", 998));
        generators.add(NODES.objectNode().put("kind", "description").put("unit", "a").put("count", 20_000_000));
        generators.add(NODES.objectNode().put("kind", "description").put("unit", "a").put("count", 20_000_001));
        generators.add(NODES.objectNode().put("kind", "description").put("unit", "\u00e9").put("count", 10_000_001));
        generators.add(NODES.objectNode().put("kind", "description").put("unit", "\uD83D\uDE00").put("count", 10_000_001));
        generators.add(NODES.objectNode().put("kind", "description").put("unit", "\\u0041").put("count", 20_000_001));
        generators.add(NODES.objectNode().put("kind", "unknown-text").put("unit", "a").put("count", 20_000_001));
        generators.add(NODES.objectNode().put("kind", "sbom-text").put("unit", "a").put("count", 20_000_001));
        generators.add(NODES.objectNode().put("kind", "unknown-integer").put("count", 1000));
        generators.add(NODES.objectNode().put("kind", "unknown-integer").put("count", 1001));
        generators.add(NODES.objectNode().put("kind", "unknown-negative-integer").put("count", 1000));
        generators.add(NODES.objectNode().put("kind", "unknown-negative-integer").put("count", 1001));
        generators.add(NODES.objectNode().put("kind", "unknown-decimal").put("count", 998));
        generators.add(NODES.objectNode().put("kind", "unknown-decimal").put("count", 999));
        generators.add(NODES.objectNode().put("kind", "unknown-decimal").put("count", 1000));
        generators.add(NODES.objectNode().put("kind", "unknown-exponent").put("count", 999));
        generators.add(NODES.objectNode().put("kind", "unknown-exponent").put("count", 1000));
        generators.add(NODES.objectNode().put("kind", "unknown-key").put("count", 50_000));
        generators.add(NODES.objectNode().put("kind", "unknown-key").put("count", 50_001));
        generators.add(NODES.objectNode().put("kind", "many-findings").put("count", 100_000));
        return generators;
    }

    private static String name(ObjectNode generator) {
        String unit = generator.path("unit").asText("");
        return "generated-" + generator.path("kind").asText() + "-" + generator.path("count").asInt()
                + (unit.isEmpty() ? "" : "-" + unit.codePoints().mapToObj(Integer::toHexString).reduce("u", (a, b) -> a + "+" + b));
    }

    /** The generators, spelled as `generate` in the Rust test spells them. */
    private static byte[] generate(ObjectNode generator) {
        int count = generator.path("count").asInt();
        String unit = generator.path("unit").asText("");
        String body = switch (generator.path("kind").asText()) {
            case "nested-unknown" -> "{\"later\":" + "[".repeat(count) + "]".repeat(count) + ",\"secrets\":[]}";
            case "nested-sbom" -> "{\"sbom\":" + "{\"a\":".repeat(count) + "1" + "}".repeat(count) + "}";
            case "nested-finding-field" -> "{\"secrets\":[{\"rule\":\"r\",\"later\":" + "[".repeat(count) + "]".repeat(count) + "}]}";
            case "description" -> "{\"secrets\":[{\"rule\":\"r\",\"description\":\"" + unit.repeat(count) + "\"}]}";
            case "unknown-text" -> "{\"later\":\"" + unit.repeat(count) + "\",\"secrets\":[]}";
            case "sbom-text" -> "{\"sbom\":{\"name\":\"" + unit.repeat(count) + "\"}}";
            case "unknown-integer" -> "{\"later\":" + "1".repeat(count) + ",\"secrets\":[]}";
            case "unknown-negative-integer" -> "{\"later\":-" + "1".repeat(count) + ",\"secrets\":[]}";
            case "unknown-decimal" -> "{\"later\":1." + "1".repeat(count) + ",\"secrets\":[]}";
            case "unknown-exponent" -> "{\"later\":1e" + "1".repeat(count) + ",\"secrets\":[]}";
            case "unknown-key" -> "{\"" + "k".repeat(count) + "\":1,\"secrets\":[]}";
            case "many-findings" -> "{\"secrets\":[" + String.join(",", java.util.Collections.nCopies(count,
                    "{\"rule\":\"r\",\"description\":\"d\",\"file\":\"f\",\"line\":1,\"fingerprint\":\"x\"}")) + "]}";
            default -> throw new AssertionError(generator);
        };
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static ObjectNode body(byte[] bytes) {
        ObjectNode source = NODES.objectNode();
        try {
            source.put("body", StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString());
        } catch (CharacterCodingException notText) {
            source.put("body_base64", Base64.getEncoder().encodeToString(bytes));
        }
        return source;
    }

    private static ObjectNode read(String name, ObjectNode source, byte[] bytes) {
        ObjectNode entry = NODES.objectNode();
        entry.put("name", name);
        entry.setAll(source);
        if (source.has("generated")) {
            // A large body is described by its generator; its outcome is what is pinned.
            entry.put("length", bytes.length);
        }
        try {
            ScanArtifacts read = CONTROL_PLANE.readValue(bytes, ScanArtifacts.class);
            if (read == null) {
                entry.put("outcome", "null");
            } else {
                entry.put("outcome", "read");
                ObjectNode summary = summary(read, !source.has("generated"));
                if (source.has("generated")) {
                    // A list is counted and its first element kept: a hundred thousand findings are not a file to commit.
                    for (String step : List.of("languages", "dependencies", "secrets", "iac", "sast", "apiEndpoints", "apiContracts",
                            "plugins", "failures")) {
                        if (summary.get(step) instanceof ArrayNode array) {
                            ObjectNode counted = NODES.objectNode().put("count", array.size());
                            counted.set("first", array.isEmpty() ? NullNode.instance : array.get(0));
                            summary.set(step, counted);
                        }
                    }
                }
                entry.set("read", summary);
            }
        } catch (JsonProcessingException refused) {
            entry.put("outcome", "refused");
            entry.put("error", refused.getClass().getSimpleName() + ": " + firstLine(refused.getOriginalMessage()));
        } catch (java.io.IOException refused) {
            entry.put("outcome", "refused");
            entry.put("error", refused.getClass().getSimpleName() + ": " + firstLine(refused.getMessage()));
        }
        return entry;
    }

    private static String firstLine(String message) {
        String text = message == null ? "" : message;
        int end = text.indexOf('\n');
        return utf8(end < 0 ? text : text.substring(0, end));
    }

    /** What the reader made of a body, step by step: present or absent, and what each finding holds. */
    private static ObjectNode summary(ScanArtifacts read, boolean whole) {
        ObjectNode s = NODES.objectNode();
        s.set("sbom", read.sbom().<JsonNode>map(sbom -> whole ? texts(sbom) : NODES.textNode("present")).orElse(NullNode.instance));
        s.set("project", read.project().<JsonNode>map(p -> NODES.objectNode().put("type", utf8(p.type())).put("version", utf8(p.version())))
                .orElse(NullNode.instance));
        s.set("languages", read.languages().<JsonNode>map(names -> {
            ArrayNode array = NODES.arrayNode();
            names.stream().map(AgentWireReferenceSetTest::utf8).sorted().forEach(array::add);
            return array;
        }).orElse(NullNode.instance));
        s.set("dependencies", list(read.dependencies(), d -> NODES.objectNode().put("identifier", utf8(d.identifier()))
                .put("severity", d.severity() == null ? null : d.severity().name()).put("packageName", utf8(d.packageName()))
                .put("installedVersion", utf8(d.installedVersion())).put("fixVersions", utf8(d.fixVersions()))
                .put("description", utf8(d.description())).put("referenceUrl", utf8(d.referenceUrl())).put("purl", utf8(d.purl()))));
        s.set("secrets", list(read.secrets(), f -> NODES.objectNode().put("rule", utf8(f.rule()))
                .put("description", whole ? utf8(f.description()) : lengthOf(f.description())).put("file", utf8(f.file()))
                .put("line", f.line()).put("fingerprint", utf8(f.fingerprint()))));
        s.set("iac", list(read.iac(), f -> NODES.objectNode().put("checkId", utf8(f.checkId())).put("checkName", utf8(f.checkName()))
                .put("file", utf8(f.file())).put("line", f.line()).put("guideline", utf8(f.guideline())).put("resource", utf8(f.resource()))));
        s.set("sast", list(read.sast(), f -> NODES.objectNode().put("ruleId", utf8(f.ruleId())).put("category", utf8(f.category()))
                .put("severity", f.severity() == null ? null : f.severity().name()).put("confidence", utf8(f.confidence()))
                .put("file", utf8(f.file())).put("line", f.line()).put("message", utf8(f.message()))
                .put("owaspCategory", utf8(f.owaspCategory()))));
        s.set("apiEndpoints", list(read.apiEndpoints(), e -> NODES.objectNode().put("method", utf8(e.method())).put("path", utf8(e.path()))
                .put("authRequired", e.authRequired()).put("authType", utf8(e.authType()))
                .put("visibility", e.visibility() == null ? null : e.visibility().name()).put("filePath", utf8(e.filePath()))
                .put("lineNumber", e.lineNumber()).put("framework", utf8(e.framework())).put("operationId", utf8(e.operationId()))
                .put("summary", utf8(e.summary())).put("tags", utf8(e.tags()))));
        s.set("apiContracts", list(read.apiContracts(), c -> {
            ObjectNode node = NODES.objectNode().put("contractPath", utf8(c.contractPath())).put("format", utf8(c.format()))
                    .put("title", utf8(c.title())).put("version", utf8(c.version())).put("endpointsCount", c.endpointsCount());
            ArrayNode paths = node.putArray("declaredPaths");
            c.declaredPaths().forEach(path -> paths.add(utf8(path)));
            return node;
        }));
        ArrayNode plugins = s.putArray("plugins");
        for (PluginStep step : read.plugins()) {
            ObjectNode node = plugins.addObject();
            switch (step) {
                case PluginStep.Produced p -> {
                    node.put("state", "produced").put("pluginId", utf8(p.pluginId())).put("manifestDigest", utf8(p.manifestDigest()))
                            .put("toolName", utf8(p.toolName())).put("toolVersion", utf8(p.toolVersion()));
                    node.set("findings", list(java.util.Optional.of(p.findings()), f -> NODES.objectNode().put("ruleId", utf8(f.ruleId()))
                            .put("severity", f.severity() == null ? null : f.severity().name()).put("file", utf8(f.file()))
                            .put("line", f.line()).put("message", utf8(f.message()))));
                    node.put("signature", p.signature() == null ? null : p.signature().wireName());
                }
                case PluginStep.NotApplicable n -> {
                    node.put("state", "not_applicable").put("pluginId", utf8(n.pluginId())).put("manifestDigest", utf8(n.manifestDigest()));
                    ArrayNode languages = node.putArray("languages");
                    n.languages().forEach(language -> languages.add(language.wireName()));
                }
                case PluginStep.Absent a -> node.put("state", "absent").put("pluginId", utf8(a.pluginId()))
                        .put("manifestDigest", utf8(a.manifestDigest())).put("reason", utf8(a.reason()));
                case PluginStep.Refused r -> node.put("state", "refused").put("pluginId", utf8(r.pluginId()))
                        .put("manifestDigest", utf8(r.manifestDigest())).put("refusal", r.refusal() == null ? null : r.refusal().wireName())
                        .put("reason", utf8(r.reason()));
            }
        }
        ArrayNode failures = s.putArray("failures");
        for (ScanArtifacts.Failure failure : read.failures()) {
            if (failure == null) {
                failures.addNull();
            } else {
                failures.addObject().put("step", utf8(failure.step())).put("reason", utf8(failure.reason()));
            }
        }
        s.set("duration", read.duration() == null ? NullNode.instance
                : NODES.objectNode().put("seconds", read.duration().getSeconds()).put("nanos", read.duration().getNano()));
        s.put("observedNothing", read.observedNothing());
        return s;
    }

    private static String lengthOf(String text) {
        return text == null ? null : "length " + text.length();
    }

    private static <T> JsonNode list(java.util.Optional<List<T>> step, java.util.function.Function<T, ObjectNode> each) {
        if (step.isEmpty()) {
            return NullNode.instance;
        }
        ArrayNode array = NODES.arrayNode();
        for (T item : step.get()) {
            if (item == null) {
                array.addNull();
            } else {
                array.add(each.apply(item));
            }
        }
        return array;
    }

    /** A text as its UTF-8 bytes say it: a lone surrogate becomes `?`, as when the fingerprint hashes it. */
    private static String utf8(String text) {
        return text == null ? null : new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    private static JsonNode texts(JsonNode node) {
        try {
            return CONTROL_PLANE.readTree(utf8(CONTROL_PLANE.writeValueAsString(node)));
        } catch (JsonProcessingException unreadable) {
            throw new AssertionError(unreadable);
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Around the result

    private static final String SEALED = "sealed-envelope-placeholder-AAAA";

    /** The claim's answer, as Spring MVC writes `AgentTask`. */
    private static ArrayNode claims() throws Exception {
        Map<String, ScanDispatcher.AgentTask> tasks = new LinkedHashMap<>();
        tasks.put("repository-sealed-key", new ScanDispatcher.AgentTask(7, 1, new ScanTask(
                new ScanTask.Target.Repository("git@github.com:org/repo.git", "main", null, SEALED, null),
                "ab12", Set.of(ScanTask.Step.SECRETS), List.of())));
        tasks.put("repository-https-token-plugins-every-step", new ScanDispatcher.AgentTask(42, 3, new ScanTask(
                new ScanTask.Target.Repository("https://gitlab.example/g/p.git", null, "services/api", null,
                        new ScanTask.Target.HttpsCredential("gitlab.example", "oauth2", SEALED)),
                null, EnumSet.allOf(ScanTask.Step.class),
                List.of(new PluginRef("a", "1".repeat(64)), new PluginRef("b", "2".repeat(64), true)))));
        tasks.put("repository-https-without-username", new ScanDispatcher.AgentTask(8, 2, new ScanTask(
                new ScanTask.Target.Repository("https://h.example/p.git", "dev", null, null,
                        new ScanTask.Target.HttpsCredential("h.example", null, SEALED)),
                null, Set.of(ScanTask.Step.SAST, ScanTask.Step.IAC), List.of())));
        tasks.put("image-by-digest", new ScanDispatcher.AgentTask(9, 1, new ScanTask(
                new ScanTask.Target.Image(new ImageReference("registry.example:5000", "team/app", "sha256:" + "ab".repeat(32)), "linux/arm64"),
                null, Set.of(ScanTask.Step.DEPENDENCIES), List.of())));
        tasks.put("image-docker-hub-no-step", new ScanDispatcher.AgentTask(10, 1, new ScanTask(
                new ScanTask.Target.Image(new ImageReference(null, "library/alpine", "3.20"), null), null, Set.of(), List.of())));
        tasks.put("image-blank-registry", new ScanDispatcher.AgentTask(11, 1, new ScanTask(
                new ScanTask.Target.Image(new ImageReference("", "library/alpine", "latest"), "linux/amd64"), null, null, null)));
        tasks.put("text-escaping", new ScanDispatcher.AgentTask(12, 1, new ScanTask(
                new ScanTask.Target.Repository("https://h.example/\"q\"\\b\u0001\u001f\u007f\u2028\u00e9\uD83D\uDE00/<>&'.git",
                        "feat/\u00e9t\u00e9\t\n\r\b\f", "a b/\u0000", null, null),
                "\u00e9", Set.of(ScanTask.Step.SECRETS), List.of(new PluginRef("\u2603", "</script>")))));
        tasks.put("largest-numbers", new ScanDispatcher.AgentTask(Long.MAX_VALUE, Integer.MAX_VALUE, new ScanTask(
                new ScanTask.Target.Repository("https://h.example/p.git", null, null, null), null, Set.of(), List.of())));
        ArrayNode cases = NODES.arrayNode();
        for (Map.Entry<String, ScanDispatcher.AgentTask> task : tasks.entrySet()) {
            String body = HTTP.writeValueAsString(task.getValue());
            cases.addObject().put("name", task.getKey()).put("body", stepsInTheirOrder(body));
        }
        return cases;
    }

    /**
     * The steps in their enum order. **`Set.copyOf` iterates in an order salted per JVM run**, so the Java control plane
     * writes a task's steps in a different order from one start to the next; any order is the same task to the agent,
     * which reads a set. The reference pins the enum's, one of the orders Java can write.
     */
    private static String stepsInTheirOrder(String body) {
        tools.jackson.databind.JsonNode steps = HTTP.readTree(body).path("task").path("steps");
        String written = HTTP.writeValueAsString(steps);
        List<String> names = new ArrayList<>();
        steps.forEach(step -> names.add(step.asString()));
        names.sort(java.util.Comparator.comparing(ScanTask.Step::valueOf));
        String ordered = HTTP.writeValueAsString(names);
        assertThat(body).containsOnlyOnce("\"steps\":" + written);
        return body.replace("\"steps\":" + written, "\"steps\":" + ordered);
    }

    private static final UUID AGENT_ID = UUID.fromString("0f8fad5b-d9cb-469f-a165-70867728950e");

    private static ArrayNode hello() throws Exception {
        Map<String, AgentsController.HelloResponse> answers = new LinkedHashMap<>();
        answers.put("local", new AgentsController.HelloResponse(AGENT_ID, "build-agent-01", AgentContract.VERSION, 1, "local"));
        answers.put("delegated-escaped-name", new AgentsController.HelloResponse(
                AGENT_ID, "Agent \"\u03b2\" \\ \u2603 \u0007", AgentContract.VERSION, 16, "delegated"));
        answers.put("nothing-known", new AgentsController.HelloResponse(null, null, AgentContract.VERSION, 0, null));
        ArrayNode cases = NODES.arrayNode();
        for (Map.Entry<String, AgentsController.HelloResponse> answer : answers.entrySet()) {
            cases.addObject().put("name", answer.getKey()).put("body", HTTP.writeValueAsString(answer.getValue()));
        }
        return cases;
    }

    /** The contract number at hello: compared once trimmed, as `String.trim` trims; refused with the controller's sentence. */
    private static ArrayNode contract() {
        AgentsController controller = controller();
        ArrayNode cases = NODES.arrayNode();
        List<String> announced = new ArrayList<>(List.of("1", " 1 ", "\t1\n", "\u00001\u001f", "01", "1.0", "", " ", "2", "\u00a01",
                "1\u2003", "v1", "\u0661", "unknown", "\"1\""));
        announced.add(null);
        for (String version : announced) {
            ObjectNode entry = cases.addObject();
            entry.put("announced", version);
            boolean compatible = AgentContract.isCompatible(version);
            entry.put("compatible", compatible);
            if (!compatible) {
                AgentProtocolService protocol = protocolOf(controller);
                // The service's one line before its answer: a missing number is announced as "".
                when(protocol.hello(any(), any())).thenReturn(
                        new AgentProtocolService.Hello.IncompatibleContract(version == null ? "" : version));
                try {
                    controller.hello(new AgentsController.HelloRequest(version, null, null, null, null, null, null), principal());
                    throw new AssertionError("a refusal");
                } catch (ResponseStatusException refused) {
                    entry.put("status", refused.getStatusCode().value());
                    entry.put("reason", refused.getReason());
                }
            }
        }
        return cases;
    }

    private static Map<String, String> helloRequests() {
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("as-the-agent-writes-it", "{\"contract_version\":\"1\",\"hostname\":\"h\",\"platform\":\"linux/amd64\","
                + "\"scanner_engine\":\"rust\",\"sealing_public_key\":\"MCowBQYDK2VuAyEA\",\"version\":\"0.11.1\"}");
        cases.put("camel-case-is-unknown", "{\"contractVersion\":\"1\",\"scannerEngine\":\"x\",\"hostname\":\"h\"}");
        cases.put("unknown-fields", "{\"contract_version\":\"1\",\"later\":{\"a\":[1]},\"capabilities\":\"plugins,sast\"}");
        cases.put("contract-number", "{\"contract_version\":1}");
        cases.put("contract-decimal", "{\"contract_version\":1.0}");
        cases.put("contract-true", "{\"contract_version\":true}");
        cases.put("contract-null", "{\"contract_version\":null}");
        cases.put("contract-object", "{\"contract_version\":{}}");
        cases.put("contract-array", "{\"contract_version\":[\"1\"]}");
        cases.put("empty-object", "{}");
        cases.put("duplicate-later-wins", "{\"contract_version\":\"2\",\"contract_version\":\"1\"}");
        cases.put("lone-surrogate", "{\"contract_version\":\"1\",\"hostname\":\"h\\uD800\"}");
        cases.put("trailing-garbage", "{\"contract_version\":\"1\"} x");
        cases.put("trailing-whitespace", "{\"contract_version\":\"1\"}\n ");
        cases.put("two-documents", "{\"contract_version\":\"1\"}{}");
        // Jackson 3's `StreamReadConstraints` nest 500 deep, not Jackson 2's 1,000.
        cases.put("nested-at-the-limit", "{\"later\":" + "[".repeat(499) + "]".repeat(499) + "}");
        cases.put("nested-past-the-limit", "{\"later\":" + "[".repeat(500) + "]".repeat(500) + "}");
        cases.put("null-literal", "null");
        cases.put("array-root", "[]");
        cases.put("empty-body", "");
        return cases;
    }

    private static Map<String, String> sealingKeyRequests() {
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("as-the-agent-writes-it", "{\"public_key\":\"MCowBQYDK2VuAyEA\",\"generation\":1760000000000,\"signature\":\"c2ln\"}");
        cases.put("camel-case-is-unknown", "{\"publicKey\":\"k\",\"generation\":1,\"signature\":\"s\"}");
        cases.put("generation-text", "{\"public_key\":\"k\",\"generation\":\"5\",\"signature\":\"s\"}");
        cases.put("generation-decimal", "{\"public_key\":\"k\",\"generation\":5.7,\"signature\":\"s\"}");
        cases.put("generation-negative", "{\"public_key\":\"k\",\"generation\":-1,\"signature\":\"s\"}");
        cases.put("generation-zero", "{\"public_key\":\"k\",\"generation\":0,\"signature\":\"s\"}");
        cases.put("generation-null", "{\"public_key\":\"k\",\"generation\":null,\"signature\":\"s\"}");
        cases.put("generation-too-big", "{\"public_key\":\"k\",\"generation\":9223372036854775808,\"signature\":\"s\"}");
        cases.put("generation-true", "{\"public_key\":\"k\",\"generation\":true,\"signature\":\"s\"}");
        cases.put("generation-empty-text", "{\"public_key\":\"k\",\"generation\":\"\",\"signature\":\"s\"}");
        cases.put("key-number", "{\"public_key\":12,\"generation\":1,\"signature\":\"s\"}");
        cases.put("unknown-fields", "{\"public_key\":\"k\",\"generation\":1,\"signature\":\"s\",\"later\":[1]}");
        cases.put("trailing-garbage", "{\"public_key\":\"k\",\"generation\":1,\"signature\":\"s\"} x");
        cases.put("generation-exponent", "{\"public_key\":\"k\",\"generation\":1e3,\"signature\":\"s\"}");
        cases.put("generation-huge-decimal", "{\"public_key\":\"k\",\"generation\":1e19,\"signature\":\"s\"}");
        cases.put("generation-padded-text", "{\"public_key\":\"k\",\"generation\":\" 5 \",\"signature\":\"s\"}");
        cases.put("empty-object", "{}");
        cases.put("null-literal", "null");
        cases.put("empty-body", "");
        return cases;
    }

    /** Request bodies as Spring MVC binds them — the auto-configured Jackson 3 mapper — field by field. */
    private static ArrayNode requests(Map<String, String> bodies, Class<? extends Record> type) throws Exception {
        ArrayNode cases = NODES.arrayNode();
        for (Map.Entry<String, String> body : bodies.entrySet()) {
            ObjectNode entry = cases.addObject().put("name", body.getKey()).put("body", body.getValue());
            try {
                Record read = HTTP.readValue(body.getValue().getBytes(StandardCharsets.UTF_8), type);
                if (read == null) {
                    entry.put("outcome", "null");
                    continue;
                }
                entry.put("outcome", "read");
                ObjectNode fields = entry.putObject("read");
                for (var component : type.getRecordComponents()) {
                    Object value = component.getAccessor().invoke(read);
                    if (value == null) {
                        fields.putNull(component.getName());
                    } else if (value instanceof Long number) {
                        fields.put(component.getName(), number);
                    } else {
                        fields.put(component.getName(), utf8(value.toString()));
                    }
                }
            } catch (tools.jackson.core.JacksonException refused) {
                entry.put("outcome", "refused");
                entry.put("error", refused.getClass().getSimpleName() + ": " + firstLine(refused.getOriginalMessage()));
            }
        }
        return cases;
    }

    /** A failure report as `reportFailure` reads it: the control plane's Jackson 2 bean, then the attempt from 1. */
    private static ArrayNode failureReports() {
        Map<String, String> bodies = new LinkedHashMap<>();
        bodies.put("as-the-agent-writes-it", "{\"attempt\":2,\"reason\":\"clone refused\",\"kind\":\"permanent\"}");
        bodies.put("no-kind", "{\"attempt\":1,\"reason\":\"r\"}");
        bodies.put("kind-padded-upper", "{\"attempt\":1,\"reason\":\"r\",\"kind\":\" PERMANENT \"}");
        bodies.put("kind-unknown", "{\"attempt\":1,\"reason\":\"r\",\"kind\":\"forever\"}");
        bodies.put("kind-number", "{\"attempt\":1,\"kind\":1}");
        bodies.put("attempt-zero", "{\"attempt\":0,\"reason\":\"r\"}");
        bodies.put("attempt-negative", "{\"attempt\":-1}");
        bodies.put("attempt-null", "{\"attempt\":null,\"reason\":\"r\"}");
        bodies.put("attempt-missing", "{\"reason\":\"r\"}");
        bodies.put("attempt-text", "{\"attempt\":\"3\"}");
        bodies.put("attempt-text-word", "{\"attempt\":\"three\"}");
        bodies.put("attempt-text-empty", "{\"attempt\":\"\"}");
        bodies.put("attempt-decimal", "{\"attempt\":2.9}");
        bodies.put("attempt-too-big", "{\"attempt\":2147483648}");
        bodies.put("attempt-true", "{\"attempt\":true}");
        bodies.put("reason-number", "{\"attempt\":1,\"reason\":12.50}");
        bodies.put("reason-object", "{\"attempt\":1,\"reason\":{}}");
        bodies.put("unknown-fields", "{\"attempt\":1,\"later\":{\"x\":[]}}");
        bodies.put("lone-surrogate", "{\"attempt\":1,\"reason\":\"a\\uD800\"}");
        bodies.put("trailing-garbage", "{\"attempt\":1} x");
        bodies.put("null-literal", "null");
        bodies.put("array-root", "[]");
        bodies.put("empty-body", "");
        ArrayNode cases = NODES.arrayNode();
        for (Map.Entry<String, String> body : bodies.entrySet()) {
            ObjectNode entry = cases.addObject().put("name", body.getKey()).put("body", body.getValue());
            AgentProtocolService.FailureReport report;
            try {
                report = CONTROL_PLANE.readValue(body.getValue().getBytes(StandardCharsets.UTF_8), AgentProtocolService.FailureReport.class);
            } catch (java.io.IOException refused) {
                entry.put("outcome", "refused");
                entry.put("error", refused.getClass().getSimpleName() + ": "
                        + firstLine(refused instanceof JsonProcessingException json ? json.getOriginalMessage() : refused.getMessage()));
                continue;
            }
            if (report == null || report.attempt() == null || report.attempt() < 1) {
                entry.put("outcome", "unreadable");
                continue;
            }
            entry.put("outcome", "read");
            entry.putObject("read").put("attempt", report.attempt()).put("reason", utf8(report.reason()))
                    .put("kind", com.asmolabs.vectispire.common.domain.scans.FailureKind.fromWire(report.kind()).wireName());
        }
        return cases;
    }

    private static ArrayNode failureAnswers() throws Exception {
        Map<String, AgentsController.FailureReportResponse> answers = new LinkedHashMap<>();
        answers.put("retried-micros", new AgentsController.FailureReportResponse(true, 1, 3, false, Instant.parse("2026-10-17T12:34:56.789012Z")));
        answers.put("retried-whole-second", new AgentsController.FailureReportResponse(true, 2, 3, false, Instant.parse("2026-10-17T12:34:56Z")));
        answers.put("retried-tenth", new AgentsController.FailureReportResponse(true, 2, 5, false, Instant.parse("2026-10-17T12:34:56.100Z")));
        answers.put("retried-nanos", new AgentsController.FailureReportResponse(true, 2, 5, false, Instant.parse("2026-10-17T12:34:56.123456789Z")));
        answers.put("retried-epoch", new AgentsController.FailureReportResponse(true, 1, 1, false, Instant.EPOCH));
        answers.put("retried-before-epoch", new AgentsController.FailureReportResponse(true, 1, 1, false, Instant.parse("1969-12-31T23:59:59.5Z")));
        answers.put("exhausted", new AgentsController.FailureReportResponse(false, 3, 3, false, null));
        answers.put("permanent", new AgentsController.FailureReportResponse(false, 1, 3, true, null));
        ArrayNode cases = NODES.arrayNode();
        for (Map.Entry<String, AgentsController.FailureReportResponse> answer : answers.entrySet()) {
            ObjectNode entry = cases.addObject().put("name", answer.getKey()).put("body", HTTP.writeValueAsString(answer.getValue()));
            Instant at = answer.getValue().retryAt();
            if (at != null) {
                entry.put("retry_at_epoch_second", at.getEpochSecond()).put("retry_at_nano", at.getNano());
            }
        }
        return cases;
    }

    /** Each route's refusal, as the controller words it for an agent whose name needs escaping. */
    private static ObjectNode refusals() throws Exception {
        AgentsController controller = controller();
        AgentProtocolService protocol = protocolOf(controller);
        HttpServletRequest request = mock(HttpServletRequest.class);
        ObjectNode out = NODES.objectNode();
        out.put("agent_name", AGENT.name());
        Map<String, AgentProtocolService.SealingKey> sealing = new LinkedHashMap<>();
        sealing.put("unreadable", new AgentProtocolService.SealingKey.Unreadable());
        sealing.put("not_pinned", new AgentProtocolService.SealingKey.NotPinned());
        sealing.put("not_verified", new AgentProtocolService.SealingKey.NotVerified());
        sealing.put("stale", new AgentProtocolService.SealingKey.Stale());
        for (Map.Entry<String, AgentProtocolService.SealingKey> outcome : sealing.entrySet()) {
            when(protocol.announceSealingKey(any(), any(), any())).thenReturn(outcome.getValue());
            refusal(out, "sealing_key_" + outcome.getKey(), () -> controller.announceSealingKey(
                    new AgentsController.SealingKeyRequest("k", 1L, "s"), principal(), request));
        }
        Map<String, AgentProtocolService.Submission> results = new LinkedHashMap<>();
        results.put("not_attested", new AgentProtocolService.Submission.NotAttested());
        results.put("unreadable", new AgentProtocolService.Submission.Unreadable());
        results.put("no_longer_yours", new AgentProtocolService.Submission.NoLongerYours());
        for (Map.Entry<String, AgentProtocolService.Submission> outcome : results.entrySet()) {
            when(protocol.submitResult(any(), org.mockito.ArgumentMatchers.anyLong(), any(), any(), any())).thenReturn(outcome.getValue());
            refusal(out, "result_" + outcome.getKey(), () -> controller.submitResult(1, new byte[0], null, principal(), request));
        }
        Map<String, AgentProtocolService.FailureOutcome> failures = new LinkedHashMap<>();
        failures.put("not_attested", new AgentProtocolService.FailureOutcome.NotAttested());
        failures.put("unreadable", new AgentProtocolService.FailureOutcome.Unreadable());
        failures.put("no_longer_yours", new AgentProtocolService.FailureOutcome.NoLongerYours());
        for (Map.Entry<String, AgentProtocolService.FailureOutcome> outcome : failures.entrySet()) {
            when(protocol.reportFailure(any(), org.mockito.ArgumentMatchers.anyLong(), any(), any(), any())).thenReturn(outcome.getValue());
            refusal(out, "failure_" + outcome.getKey(), () -> controller.reportFailure(1, new byte[0], null, principal(), request));
        }
        when(protocol.renewLease(any(), org.mockito.ArgumentMatchers.anyLong())).thenReturn(false);
        refusal(out, "heartbeat_lease_lost", () -> controller.heartbeat(1, principal()));
        refusal(out, "not_an_agent", () -> controller.heartbeat(1, null));
        when(protocol.admits(any())).thenReturn(false);
        refusal(out, "disabled", () -> controller.heartbeat(1, principal()));
        return out;
    }

    private static void refusal(ObjectNode out, String name, Runnable call) {
        try {
            call.run();
            throw new AssertionError(name + " was not refused");
        } catch (ResponseStatusException refused) {
            out.putObject(name).put("status", refused.getStatusCode().value()).put("reason", refused.getReason());
        }
    }

    private static final AgentView AGENT = new AgentView(AGENT_ID, "build \"\u03b2\" \\ 01", null, "remote", null, "delegated", true,
            2, null, null, null, null, null, null, "1", null, null, null, null, Instant.EPOCH);

    private static VectispirePrincipal principal() {
        return VectispirePrincipal.ofAgent(AGENT, null);
    }

    private static final Map<AgentsController, AgentProtocolService> PROTOCOLS = new java.util.IdentityHashMap<>();

    private static AgentsController controller() {
        AgentProtocolService protocol = mock(AgentProtocolService.class);
        when(protocol.admits(any())).thenReturn(true);
        AgentsController controller = new AgentsController(
                mock(AgentJobPoller.class), mock(RuleSetService.class), mock(ScanPlugins.class), protocol);
        PROTOCOLS.put(controller, protocol);
        return controller;
    }

    private static AgentProtocolService protocolOf(AgentsController controller) {
        return PROTOCOLS.get(controller);
    }

    // ---------------------------------------------------------------------------------------------------------

    /** `CoreConfiguration`'s bean itself — the mapper `AgentProtocolService` is given. */
    private static ObjectMapper controlPlaneMapper() {
        try {
            Method bean = CoreConfiguration.class.getDeclaredMethod("objectMapper");
            bean.setAccessible(true);
            return (ObjectMapper) bean.invoke(new CoreConfiguration());
        } catch (ReflectiveOperationException unreachable) {
            throw new AssertionError(unreachable);
        }
    }

    /** The mapper Spring Boot 4 auto-configures, which Spring MVC reads request bodies and writes answers with. */
    private static tools.jackson.databind.json.JsonMapper httpMapper() {
        AtomicReference<tools.jackson.databind.json.JsonMapper> found = new AtomicReference<>();
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class))
                .run(context -> found.set(context.getBean(tools.jackson.databind.json.JsonMapper.class)));
        return found.get();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}

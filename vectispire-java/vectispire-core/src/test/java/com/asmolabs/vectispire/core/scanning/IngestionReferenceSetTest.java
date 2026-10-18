package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueFingerprint;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.ToolKeys;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner.IacFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner.SastFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.config.CoreConfiguration;
import com.asmolabs.vectispire.core.issues.IssueSyncService;
import com.asmolabs.vectispire.core.scanning.internal.LicenseService;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * What {@link ScanIngestor} and the scan-completion status rule answer across the scanner reference outputs and the
 * ingestion edge cases, for the Rust port of {@code scanning} (task 2.8 of the control plane's port):
 * {@code vectispire-rust/reference/scanning/ingestion.json}.
 *
 * <p><b>Written before the Rust ingestion code</b>, so that the port is held to Java rather than to itself. Every case
 * records:
 *
 * <ul>
 *   <li>what {@link ScanIngestor#prepare} asked of {@link ScanIngestor.EndOfLifeSource} and {@link
 *       ScanIngestor.Enricher};
 *   <li>what {@link ScanIngestor.InventorySink} received ({@code components} and {@code apis}, with each {@code
 *       Optional} kept intact — decision 0007);
 *   <li>the {@link ScanIngestor.Observation} handed to {@link ScanIngestor.Backlog#reconcile}, with the unclipped
 *       findings and the {@code IssueSyncService.fingerprintOf} of each;
 *   <li>the clipped {@link FindingEntity} rows handed to {@link FindingRepository#saveAll}, after {@code fitToColumns};
 *   <li>the {@link ExaminedTypes} string and the scan status ({@code completed} vs {@code failed}).
 * </ul>
 */
class IngestionReferenceSetTest {

    private static final ObjectMapper CONTROL_PLANE = controlPlaneMapper();
    private static final ObjectMapper COMPACT = new ObjectMapper();
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;
    private static final Method FINGERPRINT_OF = fingerprintOfMethod();

    private static final Instant SCAN_CREATED_AT = Instant.parse("2026-10-18T12:00:00Z");
    private static final Instant PREPARE_AT = Instant.parse("2026-10-18T12:34:50.123456Z");
    private static final Instant INGEST_AT = Instant.parse("2026-10-18T12:34:56.789012Z");

    @Test
    void whatIngestionHandsTheBacklogAndWritesToTheRows() throws Exception {
        Path referenceDir = referenceDir();
        ArrayNode cases = NODES.arrayNode();

        for (Case c : scannerCases(referenceDir)) {
            cases.add(runCase(c, referenceDir));
        }
        for (Case c : contractAndEdgeCases()) {
            cases.add(runCase(c, referenceDir));
        }

        assertThat(cases.size()).isGreaterThan(120);
        ObjectNode out = RustReference.object();
        out.put("scanCreatedAt", SCAN_CREATED_AT.toString());
        out.put("prepareAt", PREPARE_AT.toString());
        out.put("ingestAt", INGEST_AT.toString());
        out.set("cases", cases);
        RustReference.expect("scanning/ingestion.json", out, IngestionReferenceSetTest.class);
    }

    // ── case model ──────────────────────────────────────────────────────────────────────────────────────────────

    private static final class Case {
        final String name;
        long scanId = 7L;
        Long repoId = 1L;
        Long containerId = null;
        ObjectNode source = NODES.objectNode();
        byte[] rawBody = null;
        /** `null` = no EndOfLifeSource bean; otherwise configured with enabled + optional result + descriptions. */
        ObjectNode endOfLife = null;
        /** `null` = no Enricher bean; otherwise `{ "off": true }` or `{ "epss": {...}, "kev": [...] }`. */
        ObjectNode enricher = null;
        /** `null` = no LicenseSource bean; otherwise the `LICENSE_BLOCKLIST` setting read by `LicenseService`. */
        String licenseBlocklist = null;
        int created = 2;
        int resolved = 1;
        int reopened = 0;
        int stillOpen = 1;
        long issueIdBase = 100L;

        Case(String name, Consumer<Case> setUp) {
            this.name = name;
            setUp.accept(this);
        }
    }

    // ── scanner reference corpus ────────────────────────────────────────────────────────────────────────────────

    private static List<Case> scannerCases(Path referenceDir) throws IOException {
        List<Case> cases = new ArrayList<>();

        // 1. Dependency scanner findings (paired with matching SBOM when one exists).
        for (Path file : listSorted(referenceDir.resolve("dependencies/findings"))) {
            String filename = file.getFileName().toString();
            Path sbomFile = referenceDir.resolve("dependencies/sbom").resolve(filename);
            boolean hasSbom = Files.exists(sbomFile);
            cases.add(new Case("scanner:dependencies:" + filename, c -> {
                c.source.put("kind", "scanner-dependencies").put("findings", "dependencies/findings/" + filename);
                if (hasSbom) {
                    c.source.put("sbom", "dependencies/sbom/" + filename);
                }
            }));
            if ("03-alpine-image.json".equals(filename)) {
                cases.add(new Case("scanner:dependencies:03-alpine-image-on-container", c -> {
                    c.scanId = 8L;
                    c.repoId = null;
                    c.containerId = 4L;
                    c.source.put("kind", "scanner-dependencies")
                            .put("findings", "dependencies/findings/" + filename)
                            .put("sbom", "dependencies/sbom/" + filename);
                    c.licenseBlocklist = "GPL-2.0-only, GPL-2.0-or-later";
                }));
            }
        }

        // 2. Every SBOM reference output with LicenseService and EndOfLifeSource active.
        for (Path file : listSorted(referenceDir.resolve("dependencies/sbom"))) {
            String filename = file.getFileName().toString();
            cases.add(new Case("scanner:sbom:" + filename, c -> {
                c.source.put("kind", "scanner-sbom").put("sbom", "dependencies/sbom/" + filename);
                c.licenseBlocklist = "GPL-2.0-only, GPL-2.0-or-later, AGPL-3.0-only";
                ObjectNode eol = NODES.objectNode().put("enabled", true);
                ArrayNode eolFindings = eol.putArray("findings");
                eolFindings.add(observedFindingNode(
                        FindingType.EOL.wireName(),
                        "endoflife.date",
                        "alpine:3.18",
                        Severity.HIGH.wireName(),
                        "alpine",
                        "3.18",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        "3.20",
                        "https://endoflife.date/alpine",
                        false,
                        "alpine 3.18 reached end of life"));
                eol.putObject("descriptions").put("alpine:3.18", "Alpine 3.18 support ended on 2025-05-01.");
                c.endOfLife = eol;
            }));
        }

        // 3. SAST outcomes (findings, absent, failure).
        for (Path file : listSorted(referenceDir.resolve("sast/outcomes"))) {
            String filename = file.getFileName().toString();
            cases.add(new Case("scanner:sast:" + filename, c -> {
                c.source.put("kind", "scanner-sast").put("outcome", "sast/outcomes/" + filename);
            }));
        }

        // 4. IaC outcomes (findings, absent).
        for (Path file : listSorted(referenceDir.resolve("iac/outcomes"))) {
            String filename = file.getFileName().toString();
            cases.add(new Case("scanner:iac:" + filename, c -> {
                c.source.put("kind", "scanner-iac").put("outcome", "iac/outcomes/" + filename);
            }));
        }

        // 5. Secrets findings (array or null).
        for (Path file : listSorted(referenceDir.resolve("secrets/findings"))) {
            String filename = file.getFileName().toString();
            cases.add(new Case("scanner:secrets:" + filename, c -> {
                c.source.put("kind", "scanner-secrets").put("findings", "secrets/findings/" + filename);
            }));
        }

        return cases;
    }

    // ── contract and edge cases ─────────────────────────────────────────────────────────────────────────────────

    private static List<Case> contractAndEdgeCases() throws Exception {
        List<Case> cases = new ArrayList<>();

        // Absent vs empty per step, and the status rule.
        cases.add(bodyCase("step:all-absent-no-failure", "{}"));
        cases.add(bodyCase(
                "step:all-absent-with-failure",
                "{\"failures\":[{\"step\":\"dependencies\",\"reason\":\"grype exited with 1\"}]}"));
        cases.add(bodyCase("step:dependencies-empty", "{\"dependencies\":[]}"));
        cases.add(bodyCase(
                "step:dependencies-empty-with-failure",
                "{\"dependencies\":[],\"failures\":[{\"step\":\"sast\",\"reason\":\"semgrep timed out\"}]}"));
        cases.add(bodyCase("step:secrets-empty", "{\"secrets\":[]}"));
        cases.add(bodyCase("step:iac-empty", "{\"iac\":[]}"));
        cases.add(bodyCase("step:sast-empty", "{\"sast\":[]}"));
        cases.add(bodyCase(
                "step:all-four-empty",
                "{\"dependencies\":[],\"secrets\":[],\"iac\":[],\"sast\":[]}"));

        // Secrets deduplication by `file:line` (first wins, null file treated as "").
        cases.add(bodyCase(
                "step:secrets-deduplication",
                "{\"secrets\":["
                        + "{\"rule\":\"aws-key\",\"description\":\"first at a:10\",\"file\":\"a.env\",\"line\":10,\"fingerprint\":\"fp1\"},"
                        + "{\"rule\":\"generic-key\",\"description\":\"second at a:10 dropped\",\"file\":\"a.env\",\"line\":10,\"fingerprint\":\"fp2\"},"
                        + "{\"rule\":\"aws-key\",\"description\":\"different line kept\",\"file\":\"a.env\",\"line\":11,\"fingerprint\":\"fp3\"},"
                        + "{\"rule\":\"null-file-1\",\"description\":\"first at :5\",\"file\":null,\"line\":5,\"fingerprint\":\"fp4\"},"
                        + "{\"rule\":\"null-file-2\",\"description\":\"second at :5 dropped\",\"file\":null,\"line\":5,\"fingerprint\":\"fp5\"},"
                        + "{\"rule\":\"empty-file\",\"description\":\"empty file collides with null file at :5\",\"file\":\"\",\"line\":5,\"fingerprint\":\"fp6\"}"
                        + "]}"));

        // SAST categories (security vs quality) and LOW-confidence downgrade across all severities.
        cases.add(bodyCase(
                "step:sast-categories-and-confidence-downgrade",
                "{\"sast\":["
                        + "{\"ruleId\":\"r-crit-low\",\"category\":\"security\",\"severity\":\"CRITICAL\",\"confidence\":\"LOW\",\"file\":\"A.java\",\"line\":1,\"message\":\"m1\",\"owaspCategory\":\"A01\"},"
                        + "{\"ruleId\":\"r-high-low\",\"category\":\"security\",\"severity\":\"HIGH\",\"confidence\":\"LOW\",\"file\":\"A.java\",\"line\":2,\"message\":\"m2\",\"owaspCategory\":null},"
                        + "{\"ruleId\":\"r-med-low\",\"category\":\"security\",\"severity\":\"MEDIUM\",\"confidence\":\"LOW\",\"file\":\"A.java\",\"line\":3,\"message\":\"m3\",\"owaspCategory\":\"A03\"},"
                        + "{\"ruleId\":\"r-low-low\",\"category\":\"security\",\"severity\":\"LOW\",\"confidence\":\"LOW\",\"file\":\"A.java\",\"line\":4,\"message\":\"m4\",\"owaspCategory\":null},"
                        + "{\"ruleId\":\"r-neg-low\",\"category\":\"security\",\"severity\":\"NEGLIGIBLE\",\"confidence\":\"LOW\",\"file\":\"A.java\",\"line\":5,\"message\":\"m5\",\"owaspCategory\":null},"
                        + "{\"ruleId\":\"r-unk-low\",\"category\":\"security\",\"severity\":\"UNKNOWN\",\"confidence\":\"LOW\",\"file\":\"A.java\",\"line\":6,\"message\":\"m6\",\"owaspCategory\":null},"
                        + "{\"ruleId\":\"r-crit-high\",\"category\":\"correctness\",\"severity\":\"CRITICAL\",\"confidence\":\"HIGH\",\"file\":\"B.java\",\"line\":7,\"message\":\"m7\",\"owaspCategory\":null},"
                        + "{\"ruleId\":\"r-high-null\",\"category\":null,\"severity\":\"HIGH\",\"confidence\":null,\"file\":\"B.java\",\"line\":8,\"message\":\"m8\",\"owaspCategory\":null},"
                        + "{\"ruleId\":\"r-low-case\",\"category\":\"security\",\"severity\":\"CRITICAL\",\"confidence\":\"low\",\"file\":\"B.java\",\"line\":9,\"message\":\"lowercase low does not downgrade\",\"owaspCategory\":null}"
                        + "]}"));

        // API inventory Optionals: decision 0007 (absent stays absent, empty stays empty).
        cases.add(bodyCase("step:apis-endpoints-empty-contracts-absent", "{\"apiEndpoints\":[],\"apiContracts\":null}"));
        cases.add(bodyCase("step:apis-endpoints-absent-contracts-empty", "{\"apiEndpoints\":null,\"apiContracts\":[]}"));
        cases.add(bodyCase("step:apis-both-empty", "{\"apiEndpoints\":[],\"apiContracts\":[]}"));
        cases.add(bodyCase(
                "step:apis-both-populated",
                "{\"apiEndpoints\":[{\"method\":\"POST\",\"path\":\"/v1/login\",\"authRequired\":false,\"authType\":null,"
                        + "\"visibility\":\"PUBLIC\",\"filePath\":\"AuthController.java\",\"lineNumber\":42,\"framework\":\"spring\","
                        + "\"operationId\":\"login\",\"summary\":\"Sign in\",\"tags\":\"auth\",\"sensitivePath\":true}],"
                        + "\"apiContracts\":[{\"contractPath\":\"openapi.yaml\",\"format\":\"openapi-3.0\",\"title\":\"API\","
                        + "\"version\":\"1.2.0\",\"endpointsCount\":1,\"declaredPaths\":[\"/v1/login\"]}]}"));

        // Plugins: Produced (with findings, empty, untrimmed/Unicode pluginId, null severity), NotApplicable, Absent, Refused.
        cases.add(bodyCase(
                "step:plugins-produced-and-other-states",
                "{\"plugins\":["
                        + "{\"state\":\"produced\",\"pluginId\":\"  Acme-Sec\\u00A0 \",\"manifestDigest\":\"" + "a".repeat(64) + "\","
                        + "\"toolName\":\"Acme Security\",\"toolVersion\":\"2.1.0\",\"signature\":\"verified\",\"findings\":["
                        + "{\"ruleId\":\"ACME-001\",\"severity\":\"CRITICAL\",\"file\":\"src/main.rs\",\"line\":12,\"message\":\"bad\"},"
                        + "{\"ruleId\":\"ACME-002\",\"severity\":null,\"file\":null,\"line\":null,\"message\":null}"
                        + "]},"
                        + "{\"state\":\"produced\",\"pluginId\":\"clean-plugin\",\"manifestDigest\":\"" + "b".repeat(64) + "\","
                        + "\"toolName\":null,\"toolVersion\":null,\"signature\":null,\"findings\":[]},"
                        + "{\"state\":\"not_applicable\",\"pluginId\":\"skipped-plugin\",\"manifestDigest\":\"" + "c".repeat(64) + "\","
                        + "\"languages\":[\"go\"]},"
                        + "{\"state\":\"absent\",\"pluginId\":\"crashed-plugin\",\"manifestDigest\":\"" + "d".repeat(64) + "\","
                        + "\"reason\":\"container exited with 2\"},"
                        + "{\"state\":\"refused\",\"pluginId\":\"unsigned-plugin\",\"manifestDigest\":\"" + "e".repeat(64) + "\","
                        + "\"refusal\":\"unsigned\",\"reason\":\"no signature\"}"
                        + "]}"));
        cases.add(bodyCase(
                "step:plugin-produced-empty-with-step-failure-stays-completed",
                "{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"clean-plugin\",\"manifestDigest\":\"" + "b".repeat(64) + "\","
                        + "\"toolName\":null,\"toolVersion\":null,\"signature\":\"verified\",\"findings\":[]}],"
                        + "\"failures\":[{\"step\":\"sast\",\"reason\":\"semgrep failed\"}]}"));
        cases.add(bodyCase(
                "step:plugins-only-non-producing-with-failure-is-failed",
                "{\"plugins\":["
                        + "{\"state\":\"not_applicable\",\"pluginId\":\"p1\",\"manifestDigest\":\"" + "c".repeat(64) + "\",\"languages\":[\"go\"]},"
                        + "{\"state\":\"absent\",\"pluginId\":\"p2\",\"manifestDigest\":\"" + "d".repeat(64) + "\",\"reason\":\"boom\"},"
                        + "{\"state\":\"refused\",\"pluginId\":\"p3\",\"manifestDigest\":\"" + "e".repeat(64) + "\",\"refusal\":\"unsigned\",\"reason\":\"unsigned\"}"
                        + "],\"failures\":[{\"step\":\"p2\",\"reason\":\"boom\"}]}"));

        // SBOM catalogue vs non-catalogue, EndOfLifeSource states, and LicenseService with DependencyGraph directness.
        String syftCatalogueWithGraph = "{\"sbom\":{"
                + "\"source\":{\"id\":\"root-app\",\"type\":\"directory\"},"
                + "\"artifacts\":["
                + "{\"id\":\"art-direct\",\"name\":\"direct-lib\",\"version\":\"1.0.0\",\"purl\":\"pkg:npm/direct-lib@1.0.0\","
                + "\"licenses\":[{\"spdxExpression\":\"GPL-3.0-only\"},{\"value\":\"MIT\"}]},"
                + "{\"id\":\"art-trans\",\"name\":\"trans-lib\",\"version\":\"2.0.0\",\"purl\":\"pkg:npm/trans-lib@2.0.0\","
                + "\"licenses\":[\"AGPL-3.0-only\",\"Apache-2.0\"]},"
                + "{\"id\":\"art-unlinked\",\"name\":\"unlinked-lib\",\"version\":\"3.0.0\",\"purl\":\"pkg:npm/unlinked-lib@3.0.0\","
                + "\"licenses\":[{\"value\":\"GPL-3.0-only\"}]}"
                + "],"
                + "\"artifactRelationships\":["
                + "{\"parent\":\"art-direct\",\"child\":\"root-app\",\"type\":\"dependency-of\"},"
                + "{\"parent\":\"art-trans\",\"child\":\"art-direct\",\"type\":\"dependency-of\"}"
                + "]},"
                + "\"dependencies\":["
                + "{\"identifier\":\"CVE-2026-1000\",\"severity\":\"HIGH\",\"packageName\":\"direct-lib\",\"installedVersion\":\"1.0.0\","
                + "\"fixVersions\":\"1.0.1\",\"description\":\"Direct vuln\",\"referenceUrl\":\"https://example.invalid/1000\",\"purl\":\"pkg:npm/direct-lib@1.0.0\"},"
                + "{\"identifier\":\"CVE-2026-2000\",\"severity\":\"MEDIUM\",\"packageName\":\"trans-lib\",\"installedVersion\":\"2.0.0\","
                + "\"fixVersions\":null,\"description\":null,\"referenceUrl\":null,\"purl\":\"pkg:npm/trans-lib@2.0.0\"}"
                + "]}";

        cases.add(new Case("step:sbom-non-catalogue-skips-eol-and-licenses-but-calls-inventory", c -> {
            withBody(c, "{\"sbom\":{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}}");
            c.licenseBlocklist = "GPL-3.0-only";
            c.endOfLife = NODES.objectNode().put("enabled", true).set("findings", NODES.arrayNode());
        }));
        cases.add(new Case("step:eol-disabled-does-not-call-source", c -> {
            withBody(c, syftCatalogueWithGraph);
            c.licenseBlocklist = "GPL-3.0-only, AGPL-3.0-only";
            c.endOfLife = NODES.objectNode().put("enabled", false);
        }));
        cases.add(new Case("step:eol-lookup-failed-omits-eol-from-examined", c -> {
            withBody(c, syftCatalogueWithGraph);
            c.licenseBlocklist = "GPL-3.0-only, AGPL-3.0-only";
            c.endOfLife = NODES.objectNode().put("enabled", true).putNull("findings");
        }));
        cases.add(new Case("step:eol-lookup-empty-includes-eol-in-examined", c -> {
            withBody(c, syftCatalogueWithGraph);
            c.licenseBlocklist = "";
            ObjectNode eol = NODES.objectNode().put("enabled", true);
            eol.putArray("findings");
            c.endOfLife = eol;
        }));
        cases.add(new Case("step:eol-and-licenses-and-enrichment-together", c -> {
            withBody(c, syftCatalogueWithGraph);
            c.licenseBlocklist = "GPL-3.0-only, AGPL-3.0-only";
            ObjectNode eol = NODES.objectNode().put("enabled", true);
            ArrayNode eolFindings = eol.putArray("findings");
            eolFindings.add(observedFindingNode(
                    FindingType.EOL.wireName(),
                    "endoflife.date",
                    "nodejs:16",
                    Severity.HIGH.wireName(),
                    "nodejs",
                    "16.20.2",
                    "pkg:generic/nodejs@16.20.2",
                    null,
                    null,
                    true,
                    null,
                    null,
                    null,
                    null,
                    "end-of-life",
                    "20.0.0",
                    "https://endoflife.date/nodejs",
                    false,
                    "nodejs 16 reached EOL"));
            // Also an EOL finding with null identifier, and one whose identifier matches a vulnerability to test
            // description map overwrite order and that enrichment only touches vulnerabilities.
            eolFindings.add(observedFindingNode(
                    FindingType.EOL.wireName(),
                    "endoflife.date",
                    null,
                    Severity.MEDIUM.wireName(),
                    "python",
                    "2.7",
                    null,
                    null,
                    null,
                    false,
                    null,
                    0.12,
                    7.5,
                    "CVSS:3.1/AV:N",
                    null,
                    null,
                    null,
                    true,
                    "null identifier eol"));
            eolFindings.add(observedFindingNode(
                    FindingType.EOL.wireName(),
                    "endoflife.date",
                    "CVE-2026-1000",
                    Severity.LOW.wireName(),
                    "legacy",
                    "1.0",
                    null,
                    null,
                    null,
                    null,
                    null,
                    0.99,
                    null,
                    null,
                    null,
                    null,
                    null,
                    true,
                    "eol sharing id with vuln"));
            eol.putObject("descriptions")
                    .put("nodejs:16", "Node.js 16 is end-of-life.")
                    .put("CVE-2026-1000", "EOL description overwrites vuln description.");
            c.endOfLife = eol;

            ObjectNode enricher = NODES.objectNode();
            enricher.putObject("epss").put("CVE-2026-1000", 0.87654);
            enricher.putArray("kev").add("CVE-2026-1000");
            c.enricher = enricher;
        }));

        // Enrichment edge cases: blank identifiers filtered out, duplicates deduplicated & sorted, enricher returning empty.
        String enrichmentVulnsBody = "{\"dependencies\":["
                + "{\"identifier\":\"CVE-2026-B\",\"severity\":\"CRITICAL\",\"packageName\":\"pkg-b\",\"installedVersion\":\"1.0\",\"fixVersions\":null,\"description\":\"desc-b1\",\"referenceUrl\":null,\"purl\":\"pkg:npm/pkg-b@1.0\"},"
                + "{\"identifier\":\"CVE-2026-A\",\"severity\":\"HIGH\",\"packageName\":\"pkg-a\",\"installedVersion\":\"1.0\",\"fixVersions\":null,\"description\":\"desc-a\",\"referenceUrl\":null,\"purl\":\"pkg:npm/pkg-a@1.0\"},"
                + "{\"identifier\":\"CVE-2026-B\",\"severity\":\"HIGH\",\"packageName\":\"pkg-b2\",\"installedVersion\":\"2.0\",\"fixVersions\":null,\"description\":\"desc-b2\",\"referenceUrl\":null,\"purl\":\"pkg:npm/pkg-b2@2.0\"},"
                + "{\"identifier\":\"   \",\"severity\":\"LOW\",\"packageName\":\"pkg-blank\",\"installedVersion\":\"1.0\",\"fixVersions\":null,\"description\":\"blank id\",\"referenceUrl\":null,\"purl\":null},"
                + "{\"identifier\":null,\"severity\":\"LOW\",\"packageName\":\"pkg-null\",\"installedVersion\":\"1.0\",\"fixVersions\":null,\"description\":\"null id\",\"referenceUrl\":null,\"purl\":null}"
                + "]}";
        cases.add(new Case("enrichment:sorted-distinct-identifiers-and-selective-application", c -> {
            withBody(c, enrichmentVulnsBody);
            ObjectNode enricher = NODES.objectNode();
            enricher.putObject("epss").put("CVE-2026-A", 0.42);
            enricher.putArray("kev").add("CVE-2026-B");
            c.enricher = enricher;
        }));
        cases.add(new Case("enrichment:switched-off-returns-empty", c -> {
            withBody(c, enrichmentVulnsBody);
            c.enricher = NODES.objectNode().put("off", true);
        }));

        // Values past their columns: unclipped in Observation and fingerprint, clipped in FindingEntity rows.
        String id300 = "CVE-2026-" + "1234567890".repeat(30);
        String pkg300 = "pkg-" + "abcdefghij".repeat(30);
        String ver300 = "1.0.0-" + "rc12345678".repeat(30);
        String purl300 = "pkg:maven/com.example/" + " artifact90".repeat(28).replace(' ', '_');
        String fix300 = "1.0.1, " + "1.0.2, ".repeat(45);
        String link600 = "https://advisories.example.invalid/" + "segment/".repeat(75);
        String file600 = "services/backend/src/main/java/" + "deep/nested/".repeat(50) + "App.java";
        String desc17000 = "Long advisory: " + "0123456789abcdef".repeat(1_070);
        String pluginId250 = "plugin-" + "abcdefghij".repeat(25);
        String toolName150 = "ToolName-" + "0123456789".repeat(15);
        String toolVer150 = "v1.0.0+" + "build12345".repeat(15);
        String cvssVec300 = "CVSS:3.1/AV:N/AC:L/" + "PR:N/UI:N/".repeat(30);
        String fixState80 = "affected-" + "status1234".repeat(8);
        String sev80 = "custom-severity-" + "level12345".repeat(7);
        String source80 = "custom-source-" + "origin1234".repeat(7);

        ObjectNode longBody = NODES.objectNode();
        longBody.putArray("dependencies").add(NODES.objectNode()
                .put("identifier", id300)
                .put("severity", "CRITICAL")
                .put("packageName", pkg300)
                .put("installedVersion", ver300)
                .put("fixVersions", fix300)
                .put("description", desc17000)
                .put("referenceUrl", link600)
                .put("purl", purl300));
        // Second dependency with empty purl so `IssueFingerprint.of` falls back to `packageName` (unclipped!).
        ((ArrayNode) longBody.get("dependencies")).add(NODES.objectNode()
                .put("identifier", id300)
                .put("severity", "HIGH")
                .put("packageName", pkg300)
                .put("installedVersion", ver300)
                .put("fixVersions", fix300)
                .put("description", "empty purl falls back to unclipped packageName")
                .put("referenceUrl", link600)
                .put("purl", ""));
        longBody.putArray("sast").add(NODES.objectNode()
                .put("ruleId", id300)
                .put("category", "security")
                .put("severity", "HIGH")
                .put("confidence", "HIGH")
                .put("file", file600)
                .put("line", 99)
                .put("message", desc17000)
                .put("owaspCategory", "A03"));
        ObjectNode longPlugin = longBody.putArray("plugins").addObject();
        longPlugin.put("state", "produced")
                .put("pluginId", pluginId250)
                .put("manifestDigest", "f".repeat(64))
                .put("toolName", toolName150)
                .put("toolVersion", toolVer150)
                .put("signature", "verified");
        longPlugin.putArray("findings").addObject()
                .put("ruleId", id300)
                .put("severity", "LOW")
                .put("file", file600)
                .put("line", 7)
                .put("message", desc17000);
        longBody.set("sbom", CONTROL_PLANE.readTree("{\"artifacts\":[]}"));

        String longBodyJson = COMPACT.writeValueAsString(longBody);
        cases.add(new Case("clip:values-past-every-column-ascii", c -> {
            withBody(c, longBodyJson);
            ObjectNode eol = NODES.objectNode().put("enabled", true);
            eol.putArray("findings").add(observedFindingNode(
                    FindingType.EOL.wireName(),
                    source80,
                    id300,
                    sev80,
                    pkg300,
                    ver300,
                    purl300,
                    file600,
                    12,
                    true,
                    "A06",
                    0.5,
                    9.8,
                    cvssVec300,
                    fixState80,
                    fix300,
                    link600,
                    false,
                    desc17000));
            eol.putObject("descriptions").put(id300, desc17000);
            c.endOfLife = eol;
        }));

        // Astral characters (surrogate pairs, 2 UTF-16 code units) straddling the exact clip boundaries:
        // 50 (at 49..51), 100 (at 99..101), 200 (at 199..201, after "plugin:" prefix = 192 + crab),
        // 255 (at 254..256), 500 (at 499..501), 16000 (at 15999..16001).
        String crab = "\uD83E\uDD80";
        String at50 = "s".repeat(49) + crab + "tail";
        String at100 = "t".repeat(99) + crab + "tail";
        String pluginAt200 = "p".repeat(192) + crab + "tail"; // "plugin:" (7) + 192 = 199, then crab at 199..201
        String at255 = "x".repeat(254) + crab + "tail";
        String at500 = "f".repeat(499) + crab + "tail";
        String at16000 = "d".repeat(15_999) + crab + "tail";

        ObjectNode astralBody = NODES.objectNode();
        astralBody.putArray("dependencies").add(NODES.objectNode()
                .put("identifier", at255)
                .put("severity", "HIGH")
                .put("packageName", at255)
                .put("installedVersion", at255)
                .put("fixVersions", at255)
                .put("description", at16000)
                .put("referenceUrl", at500)
                .put("purl", at255));
        ObjectNode astralPlugin = astralBody.putArray("plugins").addObject();
        astralPlugin.put("state", "produced")
                .put("pluginId", pluginAt200)
                .put("manifestDigest", "1".repeat(64))
                .put("toolName", at100)
                .put("toolVersion", at100)
                .put("signature", "verified");
        astralPlugin.putArray("findings").addObject()
                .put("ruleId", at255)
                .put("severity", "MEDIUM")
                .put("file", at500)
                .put("line", 1)
                .put("message", at16000);
        astralBody.set("sbom", CONTROL_PLANE.readTree("{\"artifacts\":[]}"));
        String astralBodyJson = COMPACT.writeValueAsString(astralBody);

        cases.add(new Case("clip:surrogate-pairs-straddling-column-limits", c -> {
            withBody(c, astralBodyJson);
            ObjectNode eol = NODES.objectNode().put("enabled", true);
            eol.putArray("findings").add(observedFindingNode(
                    FindingType.EOL.wireName(),
                    at50,
                    at255,
                    at50,
                    at255,
                    at255,
                    at255,
                    at500,
                    1,
                    null,
                    null,
                    null,
                    null,
                    at255,
                    at50,
                    at255,
                    at500,
                    false,
                    at16000));
            eol.putObject("descriptions").put(at255, "astral boundary");
            c.endOfLife = eol;
        }));

        // Unpaired surrogates (\uD800 high alone, \uDC00 low alone, \uD800 followed by ASCII, and \uD800\uD83D\uDE00)
        // in every fingerprint-entering field and description.
        String unpairedBody = "{"
                + "\"dependencies\":[{"
                + "\"identifier\":\"CVE-\\uD800-1\","
                + "\"severity\":\"HIGH\","
                + "\"packageName\":\"pkg-\\uDC00-name\","
                + "\"installedVersion\":\"1.0\\uD800\","
                + "\"fixVersions\":\"1.1\\uDC00\","
                + "\"description\":\"lone high \\uD800, lone low \\uDC00, high before pair \\uD800\\uD83D\\uDE00\","
                + "\"referenceUrl\":\"https://example.invalid/\\uD800\","
                + "\"purl\":\"pkg:npm/\\uD800-purl@1.0\""
                + "},{"
                + "\"identifier\":\"CVE-\\uDC00-2\","
                + "\"severity\":\"LOW\","
                + "\"packageName\":\"pkg-\\uD800-fallback\","
                + "\"installedVersion\":\"2.0\","
                + "\"fixVersions\":null,"
                + "\"description\":null,"
                + "\"referenceUrl\":null,"
                + "\"purl\":null"
                + "}],"
                + "\"secrets\":[{"
                + "\"rule\":\"secret-\\uD800-rule\","
                + "\"description\":\"secret \\uDC00 desc\","
                + "\"file\":\"src/\\uD800/config.env\","
                + "\"line\":14,"
                + "\"fingerprint\":\"ignored\""
                + "}],"
                + "\"iac\":[{"
                + "\"checkId\":\"CKV_\\uD800_1\","
                + "\"checkName\":\"check \\uDC00\","
                + "\"file\":\"infra/\\uDC00/main.tf\","
                + "\"line\":3,"
                + "\"guideline\":\"https://example.invalid/\\uDC00\","
                + "\"resource\":\"aws_s3_bucket.b\""
                + "}],"
                + "\"sast\":[{"
                + "\"ruleId\":\"sast.\\uD800.rule\","
                + "\"category\":\"security\","
                + "\"severity\":\"MEDIUM\","
                + "\"confidence\":\"HIGH\","
                + "\"file\":\"src/\\uD800\\uDC00/Lone\\uD800.java\","
                + "\"line\":8,"
                + "\"message\":\"msg \\uDC00\","
                + "\"owaspCategory\":\"A03\""
                + "}],"
                + "\"plugins\":[{"
                + "\"state\":\"produced\","
                + "\"pluginId\":\"  plug-\\uD800-\\u00A0Id  \","
                + "\"manifestDigest\":\"" + "9".repeat(64) + "\","
                + "\"toolName\":\"Tool \\uD800\","
                + "\"toolVersion\":\"1.\\uDC00\","
                + "\"signature\":\"verified\","
                + "\"findings\":[{"
                + "\"ruleId\":\"P-\\uD800\","
                + "\"severity\":\"HIGH\","
                + "\"file\":\"dir/\\uDC00.c\","
                + "\"line\":2,"
                + "\"message\":\"plugin \\uD800 msg\""
                + "}]"
                + "}]"
                + "}";
        cases.add(bodyCase("surrogates:unpaired-in-all-fingerprint-and-row-fields", unpairedBody));

        // An SBOM near the body limit (generated deterministically by both Java and Rust so the multi-megabyte JSON is
        // not committed verbatim).
        cases.add(new Case("generated:sbom-near-body-limit", c -> {
            c.source.put("kind", "generated-large-sbom")
                    .put("components", 2_000)
                    .put("padding", 1_000);
            c.licenseBlocklist = "GPL-3.0-only, AGPL-3.0-only";
            ObjectNode enricher = NODES.objectNode();
            enricher.putObject("epss").put("CVE-2026-0001", 0.95);
            enricher.putArray("kev").add("CVE-2026-0001");
            c.enricher = enricher;
        }));

        return cases;
    }

    private static Case bodyCase(String name, String json) {
        return new Case(name, c -> withBody(c, json));
    }

    private static void withBody(Case c, String json) {
        c.source.put("kind", "body").put("body", json);
        c.rawBody = json.getBytes(StandardCharsets.UTF_8);
    }

    // ── executing a case against Java's ScanIngestor ────────────────────────────────────────────────────────────

    private static ObjectNode runCase(Case c, Path referenceDir) throws Exception {
        byte[] bytes = c.rawBody != null ? c.rawBody : buildSourceBytes(c.source, referenceDir);
        ScanArtifacts artifacts = CONTROL_PLANE.readValue(bytes, ScanArtifacts.class);

        ScanEntity scan = new ScanEntity();
        scan.setId(c.scanId);
        scan.setRepoId(c.repoId);
        scan.setContainerId(c.containerId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(SCAN_CREATED_AT);

        MutableClock clock = new MutableClock(PREPARE_AT);

        AtomicBoolean eolCalled = new AtomicBoolean(false);
        Optional<ScanIngestor.EndOfLifeSource> endOfLife = buildEndOfLife(c.endOfLife, eolCalled);

        AtomicReference<List<String>> enricherAsked = new AtomicReference<>();
        Optional<ScanIngestor.Enricher> enricher = buildEnricher(c.enricher, enricherAsked);

        Optional<ScanIngestor.LicenseSource> licenses = buildLicenseSource(c.licenseBlocklist, clock);

        AtomicReference<ObjectNode> componentsCall = new AtomicReference<>();
        AtomicReference<ObjectNode> apisCall = new AtomicReference<>();
        ScanIngestor.InventorySink inventory = new ScanIngestor.InventorySink() {
            @Override
            public void components(ScanOrigin origin, JsonNode sbom, DependencyGraph graph) {
                ObjectNode recorded = NODES.objectNode();
                recorded.put("scanId", origin.id());
                if (origin.repoId() == null) {
                    recorded.putNull("repoId");
                } else {
                    recorded.put("repoId", origin.repoId());
                }
                if (origin.containerId() == null) {
                    recorded.putNull("containerId");
                } else {
                    recorded.put("containerId", origin.containerId());
                }
                recorded.put("createdAt", origin.createdAt().toString());
                recorded.put("sbomSha256", sha256Hex(utf8(sbom.toString())));
                ObjectNode probes = recorded.putObject("directnessProbes");
                for (String purl : List.of(
                        "pkg:npm/%40babel/traverse@7.22.0",
                        "pkg:npm/direct-lib@1.0.0",
                        "pkg:npm/trans-lib@2.0.0",
                        "pkg:npm/unlinked-lib@3.0.0",
                        "pkg:npm/pkg-0@1.0.0",
                        "pkg:npm/pkg-1@1.0.0",
                        "pkg:npm/pkg-1999@1.0.0")) {
                    probes.put(purl, graph.of(purl, null, null).name());
                }
                componentsCall.set(recorded);
            }

            @Override
            public void apis(
                    long scanId,
                    Long repositoryId,
                    Optional<List<ApiEndpoint>> endpoints,
                    Optional<List<ApiContract>> contracts) {
                ObjectNode recorded = NODES.objectNode();
                recorded.put("scanId", scanId);
                if (repositoryId == null) {
                    recorded.putNull("repositoryId");
                } else {
                    recorded.put("repositoryId", repositoryId);
                }
                if (endpoints.isEmpty()) {
                    recorded.putNull("endpoints");
                } else {
                    ArrayNode arr = recorded.putArray("endpoints");
                    for (ApiEndpoint ep : endpoints.get()) {
                        arr.add(NODES.objectNode()
                                .put("method", utf8(ep.method()))
                                .put("path", utf8(ep.path()))
                                .put("authRequired", ep.authRequired())
                                .put("authType", utf8(ep.authType()))
                                .put("visibility", ep.visibility() == null ? null : ep.visibility().name())
                                .put("filePath", utf8(ep.filePath()))
                                .put("lineNumber", ep.lineNumber())
                                .put("framework", utf8(ep.framework()))
                                .put("operationId", utf8(ep.operationId()))
                                .put("summary", utf8(ep.summary()))
                                .put("tags", utf8(ep.tags()))
                                .put("sensitivePath", ep.isSensitivePath()));
                    }
                }
                if (contracts.isEmpty()) {
                    recorded.putNull("contracts");
                } else {
                    ArrayNode arr = recorded.putArray("contracts");
                    for (ApiContract contract : contracts.get()) {
                        ObjectNode node = NODES.objectNode()
                                .put("contractPath", utf8(contract.contractPath()))
                                .put("format", utf8(contract.format()))
                                .put("title", utf8(contract.title()))
                                .put("version", utf8(contract.version()))
                                .put("endpointsCount", contract.endpointsCount());
                        ArrayNode paths = node.putArray("declaredPaths");
                        if (contract.declaredPaths() != null) {
                            contract.declaredPaths().forEach(p -> paths.add(utf8(p)));
                        }
                        arr.add(node);
                    }
                }
                apisCall.set(recorded);
            }
        };

        AtomicReference<ScanIngestor.Observation> observedRef = new AtomicReference<>();
        ScanIngestor.Backlog backlog = observation -> {
            observedRef.set(observation);
            List<Long> issueIds = new ArrayList<>(observation.findings().size());
            for (int i = 0; i < observation.findings().size(); i++) {
                issueIds.add(c.issueIdBase + i);
            }
            return new ScanIngestor.Reconciliation(c.created, c.resolved, c.reopened, c.stillOpen, issueIds);
        };

        AtomicBoolean saveAllCalled = new AtomicBoolean(false);
        List<FindingEntity> savedRows = new ArrayList<>();
        FindingRepository findingRows = mock(FindingRepository.class);
        when(findingRows.saveAll(any())).thenAnswer(invocation -> {
            saveAllCalled.set(true);
            Iterable<FindingEntity> iterable = invocation.getArgument(0);
            iterable.forEach(savedRows::add);
            return savedRows;
        });

        ScanIngestor ingestor =
                new ScanIngestor(backlog, findingRows, enricher, endOfLife, licenses, inventory, clock);

        ScanIngestor.Prepared prepared = ingestor.prepare(scan, artifacts);
        clock.setInstant(INGEST_AT);
        ScanIngestor.Reconciliation result = ingestor.ingest(scan, artifacts, prepared);

        boolean nothingExamined = artifacts.observedNothing() && !artifacts.failures().isEmpty();
        String status = (nothingExamined ? ScanStatus.FAILED : ScanStatus.COMPLETED).wireName();
        int findingsCount = result.created() + result.reopened() + result.stillOpen();

        ObjectNode entry = NODES.objectNode();
        entry.put("name", c.name);
        entry.set("input", serializeInput(c));

        ObjectNode prepareAsked = entry.putObject("prepareAsked");
        prepareAsked.put("eolCalled", eolCalled.get());
        if (enricherAsked.get() == null) {
            prepareAsked.putNull("enricherIdentifiers");
        } else {
            ArrayNode ids = prepareAsked.putArray("enricherIdentifiers");
            enricherAsked.get().forEach(id -> ids.add(utf8(id)));
        }
        prepareAsked.put("preparedAt", prepared.at().toString());

        ObjectNode inv = entry.putObject("inventory");
        inv.set("components", componentsCall.get() == null ? NullNode.instance : componentsCall.get());
        inv.set("apis", apisCall.get() == null ? NullNode.instance : apisCall.get());

        ScanIngestor.Observation observation = observedRef.get();
        entry.set("observation", serializeObservation(observation));

        ObjectNode rows = entry.putObject("rows");
        rows.put("saveAllCalled", saveAllCalled.get());
        ArrayNode rowItems = rows.putArray("items");
        for (FindingEntity row : savedRows) {
            rowItems.add(COMPACT.writeValueAsString(serializeFindingEntity(row)));
        }

        ObjectNode scanAfter = entry.putObject("scanAfter");
        scanAfter.put("status", status);
        scanAfter.put("examinedTypes", scan.getExaminedTypes());
        scanAfter.put("findingsCount", findingsCount);
        scanAfter.put("newIssuesCount", scan.getNewIssuesCount());
        scanAfter.put("resolvedIssuesCount", scan.getResolvedIssuesCount());

        return entry;
    }

    private static ObjectNode serializeInput(Case c) {
        ObjectNode input = NODES.objectNode();
        input.put("scanId", c.scanId);
        if (c.repoId == null) {
            input.putNull("repoId");
        } else {
            input.put("repoId", c.repoId);
        }
        if (c.containerId == null) {
            input.putNull("containerId");
        } else {
            input.put("containerId", c.containerId);
        }
        input.set("source", c.source);
        input.set("endOfLife", c.endOfLife == null ? NullNode.instance : c.endOfLife);
        input.set("enricher", c.enricher == null ? NullNode.instance : c.enricher);
        if (c.licenseBlocklist == null) {
            input.putNull("licenseBlocklist");
        } else {
            input.put("licenseBlocklist", c.licenseBlocklist);
        }
        input.putObject("reconciliation")
                .put("created", c.created)
                .put("resolved", c.resolved)
                .put("reopened", c.reopened)
                .put("stillOpen", c.stillOpen)
                .put("issueIdBase", c.issueIdBase);
        return input;
    }

    private static ObjectNode serializeObservation(ScanIngestor.Observation observation) throws Exception {
        ObjectNode out = NODES.objectNode();
        out.put("scanId", observation.scanId());
        out.put("target", targetKey(observation.target()));

        ArrayNode types = out.putArray("scannedTypes");
        observation.scannedTypes().stream()
                .map(FindingType::wireName)
                .sorted()
                .forEach(types::add);

        ArrayNode tools = out.putArray("scannedTools");
        new TreeSet<>(observation.scannedTools()).forEach(tool -> tools.add(utf8(tool)));

        ObjectNode descriptions = out.putObject("descriptions");
        Map<String, String> sortedDescriptions = new TreeMap<>();
        observation.descriptions().forEach((k, v) -> {
            if (k != null) {
                sortedDescriptions.put(utf8(k), utf8(v));
            } else {
                out.put("nullIdentifierDescription", utf8(v));
            }
        });
        sortedDescriptions.forEach(descriptions::put);

        ArrayNode findings = out.putArray("findings");
        for (ObservedFinding finding : observation.findings()) {
            String fp = invokeFingerprintOf(observation.target(), finding);
            ObjectNode node = serializeObservedFinding(finding, fp);
            findings.add(COMPACT.writeValueAsString(node));
        }
        return out;
    }

    private static ObjectNode serializeObservedFinding(ObservedFinding f, String fingerprint) {
        ObjectNode node = NODES.objectNode();
        node.put("fingerprint", fingerprint);
        node.put("type", utf8(f.type()));
        node.put("source", utf8(f.source()));
        node.put("identifier", utf8(f.identifier()));
        node.put("severity", utf8(f.severity()));
        node.put("packageName", utf8(f.packageName()));
        node.put("packageVersion", utf8(f.packageVersion()));
        node.put("purl", utf8(f.purl()));
        node.put("filePath", utf8(f.filePath()));
        if (f.line() == null) {
            node.putNull("line");
        } else {
            node.put("line", f.line());
        }
        if (f.directDependency() == null) {
            node.putNull("directDependency");
        } else {
            node.put("directDependency", f.directDependency());
        }
        node.put("owaspCategory", utf8(f.owaspCategory()));
        if (f.epssScore() == null) {
            node.putNull("epssScore");
        } else {
            node.put("epssScore", f.epssScore());
        }
        if (f.cvssScore() == null) {
            node.putNull("cvssScore");
        } else {
            node.put("cvssScore", f.cvssScore());
        }
        node.put("cvssVector", utf8(f.cvssVector()));
        node.put("fixState", utf8(f.fixState()));
        node.put("fixVersions", utf8(f.fixVersions()));
        node.put("link", utf8(f.link()));
        node.put("kev", f.kev());
        node.put("description", utf8(f.description()));
        node.put("tool", utf8(f.tool()));
        node.put("toolName", utf8(f.toolName()));
        node.put("toolVersion", utf8(f.toolVersion()));
        return node;
    }

    private static ObjectNode serializeFindingEntity(FindingEntity f) {
        ObjectNode node = NODES.objectNode();
        node.put("scanId", f.getScanId());
        if (f.getIssueId() == null) {
            node.putNull("issueId");
        } else {
            node.put("issueId", f.getIssueId());
        }
        node.put("type", utf8(f.getType()));
        node.put("source", utf8(f.getSource()));
        node.put("tool", utf8(f.getTool()));
        node.put("toolName", utf8(f.getToolName()));
        node.put("toolVersion", utf8(f.getToolVersion()));
        node.put("identifier", utf8(f.getIdentifier()));
        node.put("severity", utf8(f.getSeverity()));
        node.put("packageName", utf8(f.getPackageName()));
        node.put("packageVersion", utf8(f.getPackageVersion()));
        node.put("purl", utf8(f.getPurl()));
        node.put("filePath", utf8(f.getFilePath()));
        if (f.getLine() == null) {
            node.putNull("line");
        } else {
            node.put("line", f.getLine());
        }
        if (f.getIsDirectDependency() == null) {
            node.putNull("directDependency");
        } else {
            node.put("directDependency", f.getIsDirectDependency());
        }
        node.put("owaspCategory", utf8(f.getOwaspCategory()));
        if (f.getEpssScore() == null) {
            node.putNull("epssScore");
        } else {
            node.put("epssScore", f.getEpssScore());
        }
        if (f.getCvssScore() == null) {
            node.putNull("cvssScore");
        } else {
            node.put("cvssScore", f.getCvssScore());
        }
        node.put("cvssVector", utf8(f.getCvssVector()));
        node.put("fixState", utf8(f.getFixState()));
        node.put("fixVersions", utf8(f.getFixVersions()));
        node.put("link", utf8(f.getLink()));
        node.put("kev", Boolean.TRUE.equals(f.getIsKev()));
        node.put("description", utf8(f.getDescription()));
        node.put("createdAt", f.getCreatedAt().toString());
        return node;
    }

    // ── building inputs and collaborators from the case spec ────────────────────────────────────────────────────

    private static byte[] buildSourceBytes(ObjectNode source, Path referenceDir) throws IOException {
        String kind = source.path("kind").asText();
        return switch (kind) {
            case "body" -> source.path("body").asText().getBytes(StandardCharsets.UTF_8);
            case "scanner-dependencies" -> {
                String findingsText = Files.readString(referenceDir.resolve(source.path("findings").asText())).trim();
                JsonNode findingsNode = CONTROL_PLANE.readTree(findingsText);
                ObjectNode doc = NODES.objectNode();
                if (source.has("sbom")) {
                    String sbomText = Files.readString(referenceDir.resolve(source.path("sbom").asText())).trim();
                    doc.set("sbom", CONTROL_PLANE.readTree(sbomText));
                }
                if (findingsNode == null || findingsNode.isNull()) {
                    doc.putNull("dependencies");
                } else if (findingsNode.isArray()) {
                    doc.set("dependencies", findingsNode);
                } else if (findingsNode.isObject() && findingsNode.has("failure")) {
                    doc.putNull("dependencies");
                    doc.putArray("failures").addObject().put("step", "dependencies").put("reason", findingsNode.get("failure").asText());
                } else {
                    doc.putNull("dependencies");
                }
                yield COMPACT.writeValueAsBytes(doc);
            }
            case "scanner-sbom" -> {
                String sbomText = Files.readString(referenceDir.resolve(source.path("sbom").asText())).trim();
                ObjectNode doc = NODES.objectNode();
                doc.set("sbom", CONTROL_PLANE.readTree(sbomText));
                yield COMPACT.writeValueAsBytes(doc);
            }
            case "scanner-sast" -> {
                List<String> lines = Files.readAllLines(referenceDir.resolve(source.path("outcome").asText()));
                String tag = lines.get(0);
                yield switch (tag) {
                    case "findings" -> ("{\"sast\":" + lines.get(1) + "}").getBytes(StandardCharsets.UTF_8);
                    case "absent" -> "{\"sast\":null}".getBytes(StandardCharsets.UTF_8);
                    case "failure" -> COMPACT.writeValueAsBytes(
                            NODES.objectNode()
                                    .putNull("sast")
                                    .set("failures", NODES.arrayNode().add(
                                            NODES.objectNode().put("step", "sast").put("reason", lines.get(1)))));
                    default -> throw new AssertionError("Unknown SAST outcome tag: " + tag);
                };
            }
            case "scanner-iac" -> {
                List<String> lines = Files.readAllLines(referenceDir.resolve(source.path("outcome").asText()));
                String tag = lines.get(0);
                yield switch (tag) {
                    case "findings" -> ("{\"iac\":" + lines.get(1) + "}").getBytes(StandardCharsets.UTF_8);
                    case "absent" -> "{\"iac\":null}".getBytes(StandardCharsets.UTF_8);
                    default -> throw new AssertionError("Unknown IaC outcome tag: " + tag);
                };
            }
            case "scanner-secrets" -> {
                String findingsText = Files.readString(referenceDir.resolve(source.path("findings").asText())).trim();
                JsonNode findingsNode = CONTROL_PLANE.readTree(findingsText);
                ObjectNode doc = NODES.objectNode();
                if (findingsNode == null || findingsNode.isNull()) {
                    doc.putNull("secrets");
                } else if (findingsNode.isArray()) {
                    doc.set("secrets", findingsNode);
                } else if (findingsNode.isObject() && findingsNode.has("failure")) {
                    doc.putNull("secrets");
                    doc.putArray("failures").addObject().put("step", "secrets").put("reason", findingsNode.get("failure").asText());
                } else {
                    doc.putNull("secrets");
                }
                yield COMPACT.writeValueAsBytes(doc);
            }
            case "generated-large-sbom" -> generateLargeSbomResult(
                    source.path("components").asInt(), source.path("padding").asInt());
            default -> throw new AssertionError("Unknown source kind: " + kind);
        };
    }

    /**
     * Builds a deterministic multi-megabyte scan result whose SBOM is a Syft catalogue with {@code components}
     * packages (the first direct, the second transitive under the first, the rest contained in the root), a license
     * violation on the first and second, and a dependency vulnerability on the first and second.
     */
    private static byte[] generateLargeSbomResult(int components, int padding) {
        String pad = "p".repeat(padding);
        StringBuilder sb = new StringBuilder(components * (padding + 220));
        sb.append("{\"sbom\":{\"source\":{\"id\":\"root\",\"type\":\"directory\"},\"artifacts\":[");
        for (int i = 0; i < components; i++) {
            if (i > 0) {
                sb.append(',');
            }
            String license = (i == 0) ? "\"GPL-3.0-only\"" : (i == 1) ? "\"AGPL-3.0-only\"" : "\"MIT\"";
            sb.append("{\"id\":\"id-")
                    .append(i)
                    .append("\",\"name\":\"pkg-")
                    .append(i)
                    .append("\",\"version\":\"1.0.0\",\"purl\":\"pkg:npm/pkg-")
                    .append(i)
                    .append("@1.0.0\",\"licenses\":[")
                    .append(license)
                    .append("],\"description\":\"")
                    .append(pad)
                    .append("\"}");
        }
        sb.append("],\"artifactRelationships\":[")
                .append("{\"parent\":\"id-0\",\"child\":\"root\",\"type\":\"dependency-of\"},")
                .append("{\"parent\":\"id-1\",\"child\":\"id-0\",\"type\":\"dependency-of\"}");
        for (int i = 0; i < components; i++) {
            sb.append(",{\"parent\":\"root\",\"child\":\"id-").append(i).append("\",\"type\":\"contains\"}");
        }
        sb.append("]},\"dependencies\":[")
                .append("{\"identifier\":\"CVE-2026-0001\",\"severity\":\"CRITICAL\",\"packageName\":\"pkg-0\",")
                .append("\"installedVersion\":\"1.0.0\",\"fixVersions\":\"1.0.1\",\"description\":\"root vuln\",")
                .append("\"referenceUrl\":\"https://example.invalid/1\",\"purl\":\"pkg:npm/pkg-0@1.0.0\"},")
                .append("{\"identifier\":\"CVE-2026-0002\",\"severity\":\"MEDIUM\",\"packageName\":\"pkg-1\",")
                .append("\"installedVersion\":\"1.0.0\",\"fixVersions\":null,\"description\":null,")
                .append("\"referenceUrl\":null,\"purl\":\"pkg:npm/pkg-1@1.0.0\"}")
                .append("]}");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static Optional<ScanIngestor.EndOfLifeSource> buildEndOfLife(
            ObjectNode spec, AtomicBoolean called) {
        if (spec == null) {
            return Optional.empty();
        }
        boolean enabled = spec.path("enabled").asBoolean(false);
        return Optional.of(new ScanIngestor.EndOfLifeSource() {
            @Override
            public boolean isEnabled() {
                return enabled;
            }

            @Override
            public Optional<List<ObservedFinding>> findings(JsonNode sbom) {
                called.set(true);
                JsonNode findingsNode = spec.get("findings");
                if (findingsNode == null || findingsNode.isNull()) {
                    return Optional.empty();
                }
                List<ObservedFinding> list = new ArrayList<>();
                for (JsonNode n : findingsNode) {
                    list.add(readObservedFindingNode(n));
                }
                return Optional.of(list);
            }

            @Override
            public String describe(ObservedFinding finding) {
                JsonNode descriptions = spec.path("descriptions");
                if (finding.identifier() != null && descriptions.has(finding.identifier())) {
                    return descriptions.get(finding.identifier()).asText();
                }
                return "EOL: " + finding.identifier();
            }
        });
    }

    private static Optional<ScanIngestor.Enricher> buildEnricher(
            ObjectNode spec, AtomicReference<List<String>> asked) {
        if (spec == null) {
            return Optional.empty();
        }
        return Optional.of(identifiers -> {
            asked.set(List.copyOf(identifiers));
            if (spec.path("off").asBoolean(false)) {
                return Optional.empty();
            }
            Map<String, Double> epss = new LinkedHashMap<>();
            spec.path("epss").properties().forEach(e -> epss.put(e.getKey(), e.getValue().asDouble()));
            Set<String> kev = new TreeSet<>();
            spec.path("kev").forEach(n -> kev.add(n.asText()));
            return Optional.of(new ScanIngestor.Enrichment(epss, kev));
        });
    }

    private static Optional<ScanIngestor.LicenseSource> buildLicenseSource(String blocklist, Clock clock) {
        if (blocklist == null) {
            return Optional.empty();
        }
        SettingsService settings = mock(SettingsService.class);
        when(settings.get(Setting.LICENSE_BLOCKLIST)).thenReturn(blocklist);
        return Optional.of(new LicenseService(settings, clock));
    }

    private static ObjectNode observedFindingNode(
            String type,
            String source,
            String identifier,
            String severity,
            String packageName,
            String packageVersion,
            String purl,
            String filePath,
            Integer line,
            Boolean directDependency,
            String owaspCategory,
            Double epssScore,
            Double cvssScore,
            String cvssVector,
            String fixState,
            String fixVersions,
            String link,
            boolean kev,
            String description) {
        ObjectNode n = NODES.objectNode();
        n.put("type", type);
        n.put("source", source);
        n.put("identifier", identifier);
        n.put("severity", severity);
        n.put("packageName", packageName);
        n.put("packageVersion", packageVersion);
        n.put("purl", purl);
        n.put("filePath", filePath);
        if (line == null) {
            n.putNull("line");
        } else {
            n.put("line", line);
        }
        if (directDependency == null) {
            n.putNull("directDependency");
        } else {
            n.put("directDependency", directDependency);
        }
        n.put("owaspCategory", owaspCategory);
        if (epssScore == null) {
            n.putNull("epssScore");
        } else {
            n.put("epssScore", epssScore);
        }
        if (cvssScore == null) {
            n.putNull("cvssScore");
        } else {
            n.put("cvssScore", cvssScore);
        }
        n.put("cvssVector", cvssVector);
        n.put("fixState", fixState);
        n.put("fixVersions", fixVersions);
        n.put("link", link);
        n.put("kev", kev);
        n.put("description", description);
        return n;
    }

    private static ObservedFinding readObservedFindingNode(JsonNode n) {
        return new ObservedFinding(
                textOrNull(n, "type"),
                textOrNull(n, "source"),
                textOrNull(n, "identifier"),
                textOrNull(n, "severity"),
                textOrNull(n, "packageName"),
                textOrNull(n, "packageVersion"),
                textOrNull(n, "purl"),
                textOrNull(n, "filePath"),
                n.path("line").isNull() || n.path("line").isMissingNode() ? null : n.get("line").asInt(),
                n.path("directDependency").isNull() || n.path("directDependency").isMissingNode()
                        ? null
                        : n.get("directDependency").asBoolean(),
                textOrNull(n, "owaspCategory"),
                n.path("epssScore").isNull() || n.path("epssScore").isMissingNode()
                        ? null
                        : n.get("epssScore").asDouble(),
                n.path("cvssScore").isNull() || n.path("cvssScore").isMissingNode()
                        ? null
                        : n.get("cvssScore").asDouble(),
                textOrNull(n, "cvssVector"),
                textOrNull(n, "fixState"),
                textOrNull(n, "fixVersions"),
                textOrNull(n, "link"),
                n.path("kev").asBoolean(false),
                textOrNull(n, "description"),
                null,
                null,
                null);
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode child = node.get(field);
        return child == null || child.isNull() ? null : child.asText();
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────────

    private static String invokeFingerprintOf(ScanTarget target, ObservedFinding finding) throws Exception {
        if (target == null) {
            return null;
        }
        String viaIssueSync = (String) FINGERPRINT_OF.invoke(null, target, finding);
        FindingType type = FindingType.fromWireName(finding.type()).orElseThrow();
        String direct = type.toolScoped()
                ? IssueFingerprint.ofTool(target, type, finding.tool(), finding.identifier(), finding.filePath())
                : IssueFingerprint.of(new IssueFingerprint.Input(
                        target,
                        type,
                        finding.identifier(),
                        finding.purl(),
                        finding.packageName(),
                        finding.filePath()));
        assertThat(direct).isEqualTo(viaIssueSync);
        return viaIssueSync;
    }

    private static Method fingerprintOfMethod() {
        try {
            Method method =
                    IssueSyncService.class.getDeclaredMethod("fingerprintOf", ScanTarget.class, ObservedFinding.class);
            method.setAccessible(true);
            return method;
        } catch (ReflectiveOperationException unreachable) {
            throw new AssertionError(unreachable);
        }
    }

    private static ObjectMapper controlPlaneMapper() {
        try {
            Method bean = CoreConfiguration.class.getDeclaredMethod("objectMapper");
            bean.setAccessible(true);
            return (ObjectMapper) bean.invoke(new CoreConfiguration());
        } catch (ReflectiveOperationException unreachable) {
            throw new AssertionError(unreachable);
        }
    }

    private static Path referenceDir() {
        String dir = System.getProperty("vectispire.rust.reference");
        assertThat(dir).as("vectispire.rust.reference is set by vectispire-core's test task").isNotBlank();
        return Path.of(dir);
    }

    private static List<Path> listSorted(Path dir) throws IOException {
        try (Stream<Path> stream = Files.list(dir)) {
            return stream.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
        }
    }

    private static String targetKey(ScanTarget target) {
        if (target == null) {
            return null;
        }
        return switch (target) {
            case ScanTarget.Repository r -> "repo:" + r.id();
            case ScanTarget.Container c -> "container:" + c.id();
        };
    }

    /** A text as its UTF-8 bytes say it: a lone surrogate becomes `?`, as when the fingerprint hashes it. */
    private static String utf8(String text) {
        return text == null ? null : new String(text.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    private static String sha256Hex(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static final class MutableClock extends Clock {
        private Instant current;

        MutableClock(Instant initial) {
            this.current = initial;
        }

        void setInstant(Instant next) {
            this.current = next;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }
    }
}

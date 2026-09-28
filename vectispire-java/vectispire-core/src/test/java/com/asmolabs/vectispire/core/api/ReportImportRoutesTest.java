package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Coverage and test reports from declared internal sources, through the real routes and the real
 * filter chain (decision 0032 §7): what a declaration needs, every refusal of 0017 §7 in its order
 * and with its status, the readers' guards reached over HTTP, and what an accepted report records.
 */
@DisplayName("coverage and test-report imports, through the routes")
class ReportImportRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private CoverageImportRepository coverageImports;

    @Autowired
    private TestReportImportRepository testReportImports;

    @Autowired
    private TestSuiteResultRepository suites;

    private long project;
    private long inScope;
    private long alsoInScope;
    private long outOfScope;

    private record Key(String id, String secret) {}

    static final String JACOCO = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            + "<!DOCTYPE report PUBLIC \"-//JACOCO//DTD Report 1.1//EN\" \"report.dtd\"><report name=\"app\">"
            + "<package name=\"a\"><counter type=\"LINE\" missed=\"9\" covered=\"1\"/></package>"
            + "<counter type=\"LINE\" missed=\"20\" covered=\"80\"/><counter type=\"BRANCH\" missed=\"5\" covered=\"15\"/>"
            + "</report>";

    static final String JUNIT = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><testsuite name=\"com.example.AppTest\">"
            + "<testcase name=\"a\"/><testcase name=\"b\"><failure message=\"no\"/></testcase>"
            + "<testcase name=\"c\"><skipped/></testcase></testsuite>";

    @BeforeEach
    void estate() throws Exception {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity entity = new ProjectEntity();
        entity.setSolutionId(solutions.save(solution).getId());
        entity.setName("ledger");
        entity.setCreatedAt(Instant.now());
        project = projects.save(entity).getId();
        inScope = repository(project);
        alsoInScope = repository(project);
        outOfScope = repository(null);
    }

    private long repository(Long projectId) throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/r-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long id = repositories.save(repository).getId();
        if (projectId != null) {
            mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + id), asAdmin()))
                    .andExpect(status().isNoContent());
        }
        return id;
    }

    private Key key(Map<String, Object> body) throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return new Key(answer.path("key").path("id").asText(), answer.path("secret").asText());
    }

    private Key key(String... scopes) throws Exception {
        return key(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of(scopes)));
    }

    private String governor() {
        return tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
    }

    private ResultActions declare(Map<String, Object> body) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/sarif-sources"), governor())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private Map<String, Object> source(String slug, Key key, List<String> kinds) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slug", slug);
        body.put("name", "Ledger CI");
        body.put("api_key_id", key.id());
        body.put("project_id", project);
        if (kinds != null) {
            body.put("kinds", kinds);
        }
        if (kinds == null || kinds.contains("sarif")) {
            body.put("tools", List.of("Semgrep OSS"));
        }
        return body;
    }

    /** A key holding report_import, declared for both reports on the project. */
    private Key declaredReportKey(String slug) throws Exception {
        Key key = key("report_import");
        declare(source(slug, key, List.of("coverage", "test_report"))).andExpect(status().isCreated());
        return key;
    }

    private ResultActions coverage(String bearer, long repositoryId, String query, byte[] document) throws Exception {
        return mvc.perform(bearer(post("/api/v1/repositories/" + repositoryId + "/coverage-imports" + query), bearer)
                .contentType(MediaType.APPLICATION_XML)
                .content(document));
    }

    private ResultActions coverage(Key key, long repositoryId, String document) throws Exception {
        return coverage(key.secret(), repositoryId, "?format=jacoco", document.getBytes(StandardCharsets.UTF_8));
    }

    private ResultActions tests(String bearer, long repositoryId, MediaType type, byte[] document) throws Exception {
        return mvc.perform(bearer(post("/api/v1/repositories/" + repositoryId + "/test-report-imports"), bearer)
                .contentType(type)
                .content(document));
    }

    private ResultActions tests(Key key, long repositoryId, String document) throws Exception {
        return tests(key.secret(), repositoryId, MediaType.APPLICATION_XML, document.getBytes(StandardCharsets.UTF_8));
    }

    private static MockHttpServletRequestBuilder bearer(MockHttpServletRequestBuilder request, String bearer) {
        return request.header("Authorization", "Bearer " + bearer);
    }

    private long refusals() {
        return auditLog.findAll().stream()
                .filter(entry -> AuditOperation.REPORT_IMPORT_REFUSED.wireName().equals(entry.getOperationType()))
                .count();
    }

    private List<String> operations() {
        return auditLog.findAll().stream().map(entry -> entry.getOperationType()).toList();
    }

    static byte[] zip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.setLevel(Deflater.BEST_COMPRESSION);
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }

    @Nested
    @DisplayName("declaring a source's kinds")
    class Declaring {

        @Test
        @DisplayName("a declaration without kinds is a SARIF source, as every source before them was")
        void sarifByDefault() throws Exception {
            declare(source("old-client", key("sarif_import"), null))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.kinds").value(Matchers.contains("sarif")));
        }

        @Test
        @DisplayName("each kind needs its scope on the key, and tools belong to SARIF alone")
        void whatEachKindNeeds() throws Exception {
            declare(source("no-scope", key("sarif_import"), List.of("sarif", "coverage")))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("report_import")));
            declare(source("no-sarif-scope", key("report_import"), List.of("sarif")))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("sarif_import")));

            Map<String, Object> tooled = source("tooled", key("report_import"), List.of("coverage"));
            tooled.put("tools", List.of("SonarQube"));
            declare(tooled).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("delivers no SARIF")));
            declare(source("nothing", key("report_import"), List.of())).andExpect(status().isBadRequest());
            declare(source("clover", key("report_import"), List.of("clover")))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("\"clover\" is none of them")));

            declare(source("both", key("sarif_import", "report_import"), List.of("test_report", "sarif", "coverage")))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.kinds").value(Matchers.contains("sarif", "coverage", "test_report")))
                    .andExpect(jsonPath("$.tools[0]").value("semgrep oss"));
        }
    }

    @Nested
    @DisplayName("an accepted report")
    class Accepted {

        @Test
        @DisplayName("coverage records the report's own totals, the pipeline's word and the document's hash")
        void coverageRecorded() throws Exception {
            Key key = declaredReportKey("ledger-ci");

            coverage(key.secret(), inScope, "?format=jacoco&commit=4F2A9C1&branch=release/2.4",
                            JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.sourceSlug").value("ledger-ci"))
                    .andExpect(jsonPath("$.repoId").value(inScope))
                    .andExpect(jsonPath("$.format").value("jacoco"))
                    .andExpect(jsonPath("$.linesCovered").value(80))
                    .andExpect(jsonPath("$.linesTotal").value(100))
                    .andExpect(jsonPath("$.branchesCovered").value(15))
                    .andExpect(jsonPath("$.branchesTotal").value(20))
                    .andExpect(jsonPath("$.commit").value("4f2a9c1"))
                    .andExpect(jsonPath("$.branch").value("release/2.4"))
                    .andExpect(jsonPath("$.apiKeyId").value(key.id()))
                    .andExpect(jsonPath("$.documentSha256").value(Matchers.matchesPattern("[0-9a-f]{64}")));
            assertThat(operations()).contains(AuditOperation.COVERAGE_IMPORTED.wireName());

            // lcov, declared: no branch counted is no branch figure — null on the wire, not 0 of 0.
            coverage(key.secret(), inScope, "?format=lcov",
                            "SF:a.ts\nDA:1,1\nDA:2,0\nend_of_record\n".getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.linesCovered").value(1))
                    .andExpect(jsonPath("$.branchesTotal").value(Matchers.nullValue()))
                    .andExpect(jsonPath("$.commit").value(Matchers.nullValue()));

            mvc.perform(authenticated(get("/api/v1/repositories/" + inScope + "/coverage-imports"), asAdmin()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].format").value("lcov"))
                    .andExpect(jsonPath("$[1].format").value("jacoco"));
            mvc.perform(authenticated(get("/api/v1/repositories/999999/coverage-imports"), asAdmin()))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("a test report records its totals and its suites; a zip of them is one import")
        void testReportRecorded() throws Exception {
            Key key = declaredReportKey("ledger-ci");

            tests(key, inScope, JUNIT)
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.format").value("junit"))
                    .andExpect(jsonPath("$.documentsCount").value(1))
                    .andExpect(jsonPath("$.suitesCount").value(1))
                    .andExpect(jsonPath("$.testsCount").value(3))
                    .andExpect(jsonPath("$.failuresCount").value(1))
                    .andExpect(jsonPath("$.errorsCount").value(0))
                    .andExpect(jsonPath("$.skippedCount").value(1));

            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("TEST-com.example.AppTest.xml", JUNIT.getBytes(StandardCharsets.UTF_8));
            entries.put("TEST-com.example.OtherTest.xml", ("<testsuite name=\"com.example.OtherTest\">"
                    + "<testcase name=\"x\"><error/></testcase></testsuite>").getBytes(StandardCharsets.UTF_8));
            entries.put("com.example.AppTest.txt", "Tests run: 3".getBytes(StandardCharsets.UTF_8));
            long id = json.readTree(tests(key.secret(), inScope, MediaType.parseMediaType("application/zip"), zip(entries))
                            .andExpect(status().isCreated())
                            .andExpect(jsonPath("$.format").value("junit-zip"))
                            .andExpect(jsonPath("$.documentsCount").value(2))
                            .andExpect(jsonPath("$.testsCount").value(4))
                            .andExpect(jsonPath("$.errorsCount").value(1))
                            .andReturn().getResponse().getContentAsString())
                    .path("id").asLong();

            assertThat(suites.findByImportIdInOrderByImportIdAscIdAsc(List.of(id)))
                    .extracting(TestSuiteResultEntity::getName)
                    .containsExactly("com.example.AppTest", "com.example.OtherTest");
            assertThat(operations()).contains(AuditOperation.TEST_REPORT_IMPORTED.wireName());
            mvc.perform(authenticated(get("/api/v1/repositories/" + inScope + "/test-report-imports"), asAuditor()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].format").value("junit-zip"))
                    .andExpect(jsonPath("$.length()").value(2));
        }
    }

    @Nested
    @DisplayName("the refusals of 0017 §7, in its order")
    class Refusals {

        @Test
        @DisplayName("a session is not a source (403), even the administrator's")
        void session() throws Exception {
            coverage(asAdmin(), inScope, "?format=jacoco", JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("a session is not a source")));
            tests(asAdmin(), inScope, MediaType.APPLICATION_XML, JUNIT.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isForbidden());
            assertThat(coverageImports.count()).isZero();
        }

        @Test
        @DisplayName("a key without report_import never reaches the route (403) — a SARIF source's key included")
        void missingScope() throws Exception {
            Key sarif = key("sarif_import");
            declare(source("sarif-only", sarif, List.of("sarif"))).andExpect(status().isCreated());

            coverage(sarif, inScope, JACOCO)
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("report_import")));
            tests(key("read"), inScope, JUNIT).andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("a key no enabled source is declared for (403), audited — and before the repository is looked at")
        void undeclaredOrDisabled() throws Exception {
            Key stranger = key("report_import");

            coverage(stranger, inScope, JACOCO)
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not declared as an enabled source")));
            // A repository that does not exist answers the same 403: the key is refused for what it
            // is before anything is said about the estate.
            tests(stranger, 999_999, JUNIT).andExpect(status().isForbidden());
            assertThat(refusals()).isEqualTo(2);

            Key declared = declaredReportKey("paused-ci");
            long id = json.readTree(mvc.perform(authenticated(get("/api/v1/sarif-sources"), governor()))
                            .andReturn().getResponse().getContentAsString()).path(0).path("id").asLong();
            mvc.perform(authenticated(put("/api/v1/sarif-sources/" + id + "/enabled"), governor())
                            .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                    .andExpect(status().isOk());
            coverage(declared, inScope, JACOCO).andExpect(status().isForbidden());
            assertThat(refusals()).isEqualTo(3);
        }

        @Test
        @DisplayName("a kind the source is not declared for (403), audited — both ways, SARIF included")
        void wrongKind() throws Exception {
            Key coverageOnly = key("sarif_import", "report_import");
            declare(source("coverage-only", coverageOnly, List.of("coverage"))).andExpect(status().isCreated());

            tests(coverageOnly, inScope, JUNIT)
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not declared to deliver test_report")));
            // Before the scope of the repository: out of scope, still the kind's 403.
            tests(coverageOnly, outOfScope, JUNIT).andExpect(status().isForbidden());
            assertThat(refusals()).isEqualTo(2);

            // The key holds sarif_import, and its source was not declared for SARIF: refused.
            mvc.perform(post("/api/v1/repositories/" + inScope + "/sarif-imports")
                            .header("Authorization", "Bearer " + coverageOnly.secret())
                            .contentType("application/sarif+json")
                            .content(SarifImportRoutesTest.sarif("Semgrep OSS", "1", "r", "a.py")))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not declared to deliver SARIF")));
            assertThat(operations()).contains(AuditOperation.SARIF_IMPORT_REFUSED.wireName());
            assertThat(testReportImports.count()).isZero();
        }

        @Test
        @DisplayName("a repository hidden from the key, absent, or outside the source's scope answers as absent (404)")
        void hiddenAbsentOrOutOfScope() throws Exception {
            Key key = declaredReportKey("ledger-ci");
            Key restricted = key(Map.of("name", "one-repo-" + System.nanoTime(), "scopes", List.of("report_import"),
                    "target_kind", "repository", "target_id", inScope));
            declare(source("one-repo", restricted, List.of("coverage"))).andExpect(status().isCreated());

            String absent = detailOf(coverage(key, 999_999, JACOCO).andExpect(status().isNotFound()).andReturn());
            String hidden = detailOf(coverage(restricted, alsoInScope, JACOCO).andExpect(status().isNotFound()).andReturn());
            long before = refusals();
            String outside = detailOf(coverage(key, outOfScope, JACOCO).andExpect(status().isNotFound()).andReturn());

            assertThat(hidden).isEqualTo(absent.replace("999999", String.valueOf(alsoInScope)));
            assertThat(outside).isEqualTo(absent.replace("999999", String.valueOf(outOfScope)));
            assertThat(refusals()).as("out of scope is a claim, and audited").isEqualTo(before + 1);
            coverage(restricted, inScope, JACOCO).andExpect(status().isCreated());
        }

        @Test
        @DisplayName("past the route's ceiling (413), refused on the declared length before a byte is read")
        void oversized() throws Exception {
            Key key = declaredReportKey("ledger-ci");
            byte[] coverageBody = new byte[16 * 1024 * 1024 + 1];
            Arrays.fill(coverageBody, (byte) ' ');
            byte[] testBody = new byte[32 * 1024 * 1024 + 1];
            Arrays.fill(testBody, (byte) ' ');

            coverage(key.secret(), inScope, "?format=jacoco", coverageBody)
                    .andExpect(status().isContentTooLarge())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("this route accepts")));
            tests(key.secret(), inScope, MediaType.APPLICATION_XML, testBody).andExpect(status().isContentTooLarge());
            // The default of 1 MB would have refused a body of two: the routes keep their own.
            byte[] twoMegabytes = new byte[2 * 1024 * 1024];
            Arrays.fill(twoMegabytes, (byte) ' ');
            coverage(key.secret(), inScope, "?format=jacoco", twoMegabytes).andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("a body that does not read as its declared format, or a format not declared (400)")
        void malformed() throws Exception {
            Key key = declaredReportKey("ledger-ci");

            coverage(key.secret(), inScope, "", JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("jacoco, cobertura, lcov")));
            coverage(key.secret(), inScope, "?format=cobertura", JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not <coverage>")));
            coverage(key.secret(), inScope, "?format=lcov", JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest());
            tests(key.secret(), inScope, MediaType.parseMediaType("application/zip"), JUNIT.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not a zip archive")));
            tests(key, inScope, "<testsuite name=\"s\"><testcase name=\"a\">")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("not well-formed")));
            coverage(key.secret(), inScope, "?format=jacoco&commit=main", JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("hexadecimal")));
            coverage(key.secret(), inScope, "?format=jacoco&branch=" + "b".repeat(256), JACOCO.getBytes(StandardCharsets.UTF_8))
                    .andExpect(status().isBadRequest());
            assertThat(coverageImports.count()).isZero();
            assertThat(testReportImports.count()).isZero();
        }

        @Test
        @DisplayName("a report that counts nothing (400): not 0 %, not all passed")
        void empty() throws Exception {
            Key key = declaredReportKey("ledger-ci");

            coverage(key, inScope, "<!DOCTYPE report PUBLIC \"-//JACOCO//DTD Report 1.1//EN\" \"report.dtd\"><report name=\"x\"/>")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("counts no line")));
            tests(key, inScope, "<testsuites name=\"empty\"/>")
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("holds no test case")));
            coverage(key.secret(), inScope, "?format=jacoco", new byte[0]).andExpect(status().isBadRequest());
            assertThat(coverageImports.count()).isZero();
            assertThat(testReportImports.count()).isZero();
        }

        @Test
        @DisplayName("an external entity is refused (400), and the file it names never reaches the answer")
        void xxe(@TempDir Path directory) throws Exception {
            Key key = declaredReportKey("ledger-ci");
            Path secret = Files.writeString(directory.resolve("secret.txt"), "database password hunter2");

            String document = "<?xml version=\"1.0\"?><!DOCTYPE report [<!ENTITY xxe SYSTEM \"" + secret.toUri() + "\">]>"
                    + "<report name=\"&xxe;\"><counter type=\"LINE\" missed=\"0\" covered=\"1\"/></report>";
            String detail = detailOf(coverage(key, inScope, document).andExpect(status().isBadRequest()).andReturn());
            String junit = detailOf(tests(key, inScope, "<!DOCTYPE testsuite [<!ENTITY xxe SYSTEM \"" + secret.toUri()
                            + "\">]><testsuite name=\"s\"><testcase name=\"&xxe;\"/></testsuite>")
                    .andExpect(status().isBadRequest()).andReturn());

            assertThat(detail).contains("internal DTD subset").doesNotContain("hunter2");
            assertThat(junit).doesNotContain("hunter2");
            assertThat(coverageImports.count()).isZero();
        }

        @Test
        @DisplayName("a zip bomb is refused (400) while it inflates, and records nothing")
        void zipBomb() throws Exception {
            Key key = declaredReportKey("ledger-ci");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
                zip.setLevel(Deflater.BEST_COMPRESSION);
                zip.putNextEntry(new ZipEntry("TEST-bomb.xml"));
                zip.write("<testsuite name=\"s\">".getBytes(StandardCharsets.UTF_8));
                byte[] spaces = new byte[1 << 20];
                Arrays.fill(spaces, (byte) ' ');
                for (int i = 0; i < 40; i++) {
                    zip.write(spaces);
                }
                zip.write("<testcase name=\"t\"/></testsuite>".getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
            assertThat(bytes.size()).as("well under the route's ceiling once deflated").isLessThan(1_000_000);

            tests(key.secret(), inScope, MediaType.parseMediaType("application/zip"), bytes.toByteArray())
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.detail").value(Matchers.containsString("inflates past")));
            assertThat(testReportImports.count()).isZero();
        }
    }
}

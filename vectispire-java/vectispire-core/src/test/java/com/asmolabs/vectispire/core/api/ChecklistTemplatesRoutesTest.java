package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.checklists.ChecklistLayoutForm;
import com.asmolabs.vectispire.core.checklists.ChecklistVersionView;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Checklist templates through the real routes and the real filter chain (decision 0032 §3, §4, §8,
 * §9): a workbook imported as a draft, its layout confirmed, its items paired with the previous
 * version, published — by somebody else when four-eyes is on — derived and retired, each refusal with
 * its status and its words, each write in the audit log and the two that change what projects attest
 * to in the SIEM's queue.
 */
@DisplayName("checklist templates, through the routes")
class ChecklistTemplatesRoutesTest extends ApiTestBase {

    private static final String BASE = "/api/v1/checklist-templates";
    private static final String XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private ChecklistTemplateVersionRepository versions;

    private String importerName;
    private String importer;
    private String reviewerName;
    private String reviewer;

    @BeforeEach
    void accounts() {
        importerName = "importer-" + System.nanoTime();
        importer = tokenFor(importerName, Role.CISO, false);
        reviewerName = "reviewer-" + System.nanoTime();
        reviewer = tokenFor(reviewerName, Role.CISO, false);
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
    }

    @Nested
    @DisplayName("importing a workbook")
    class Importing {

        @Test
        @DisplayName("makes a draft of the file whole — its bytes, SHA-256 and size — and creates the template")
        void importsADraft() throws Exception {
            byte[] workbook = ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST);

            JsonNode version = read(mvc.perform(authenticated(post(BASE + "/release/versions"), importer)
                            .param("name", "Release checklist").param("label", "2026")
                            .contentType(XLSX).content(workbook))
                    .andExpect(status().isCreated()));

            assertThat(version.at("/templateSlug").asText()).isEqualTo("release");
            assertThat(version.at("/templateName").asText()).isEqualTo("Release checklist");
            assertThat(version.at("/version/ordinal").asInt()).isEqualTo(1);
            assertThat(version.at("/version/label").asText()).isEqualTo("2026");
            assertThat(version.at("/version/status").asText()).isEqualTo("draft");
            assertThat(version.at("/version/revision").asInt()).isEqualTo(1);
            assertThat(version.at("/version/sourceSha256").asText()).isEqualTo(Digests.sha256Hex(workbook));
            assertThat(version.at("/version/sourceSize").asLong()).isEqualTo(workbook.length);
            assertThat(version.at("/version/layoutConfirmed").asBoolean()).isFalse();
            assertThat(version.at("/version/itemCount").asLong()).isZero();
            assertThat(version.at("/version/previousOrdinal").isNull()).isTrue();
            assertThat(version.at("/layout").isNull()).as("the reader only proposes").isTrue();
            assertThat(version.at("/items")).isEmpty();

            assertThat(entries("CHECKLIST_TEMPLATE_IMPORTED")).singleElement().satisfies(entry -> {
                assertThat(entry.getResourceId()).isEqualTo("release/1");
                assertThat(entry.getDescription()).contains(Digests.sha256Hex(workbook));
            });
        }

        @Test
        @DisplayName("is the security lead's: an administrator and the governor may, a champion, an auditor or a reader may not")
        void writingIsTheSecurityLeads() throws Exception {
            byte[] workbook = ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST);
            for (Role refused : List.of(Role.SECURITY_CHAMPION, Role.AUDITOR, Role.USER)) {
                importWorkbook(tokenFor("refused-" + refused + "-" + System.nanoTime(), refused, false), "denied", workbook, "")
                        .andExpect(status().isForbidden());
            }
            importWorkbook(asAdmin(), "by-admin", workbook, "").andExpect(status().isCreated());
            importWorkbook(tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false), "by-governor", workbook, "")
                    .andExpect(status().isCreated());
            mvc.perform(post(BASE + "/anonymous/versions").contentType(XLSX).content(workbook))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("refuses a body that is not a workbook, in words (400)")
        void refusesWhatIsNoWorkbook() throws Exception {
            MvcResult refused = importWorkbook(importer, "release", "not a spreadsheet".getBytes(), "")
                    .andExpect(status().isBadRequest()).andReturn();
            assertThat(detailOf(refused)).isNotBlank();

            // Refused before the service is reached: Spring requires the body, and says so.
            MvcResult empty = importWorkbook(importer, "release", new byte[0], "").andExpect(status().isBadRequest())
                    .andReturn();
            assertThat(detailOf(empty)).isNotBlank();
        }

        @Test
        @DisplayName("refuses a body past its ceiling before reading it (413)")
        void refusesAnOversizedWorkbook() throws Exception {
            byte[] tooLarge = new byte[10 * 1024 * 1024 + 1];
            MvcResult refused = importWorkbook(importer, "release", tooLarge, "")
                    .andExpect(status().is(413)).andReturn();
            assertThat(detailOf(refused)).contains("10485760 bytes");
        }

        @Test
        @DisplayName("refuses a slug that is not one, and a second draft while the first is open")
        void refusesASecondDraft() throws Exception {
            byte[] workbook = ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST);
            assertThat(detailOf(importWorkbook(importer, "Release_Checklist", workbook, "")
                    .andExpect(status().isBadRequest()).andReturn())).contains("slug");

            importWorkbook(importer, "release", workbook, "").andExpect(status().isCreated());
            assertThat(detailOf(importWorkbook(reviewer, "release", workbook, "").andExpect(status().isConflict())
                    .andReturn())).contains("already has a draft");
        }
    }

    @Nested
    @DisplayName("previewing and confirming a draft")
    class Confirming {

        @Test
        @DisplayName("the preview proposes from the structure — the answer column and its words — and shows the sheet")
        void previewProposes() throws Exception {
            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated());

            // Read by an auditor: reading templates is governance reading.
            JsonNode preview = read(mvc.perform(authenticated(get(BASE + "/release/versions/1/preview"), asAuditor()))
                    .andExpect(status().isOk()));

            assertThat(preview.at("/sheets").toString()).isEqualTo("[\"Instructions\",\"Checklist\",\"Values\"]");
            assertThat(preview.at("/sheet").asText()).isEqualTo("Checklist");
            assertThat(preview.at("/proposal/columns/answer").asText()).isEqualTo("F");
            assertThat(preview.at("/proposal/answerValues").toString()).isEqualTo("[\"Done\",\"Not done\"]");
            assertThat(preview.at("/proposal/firstItemRow").asInt()).isEqualTo(7);
            assertThat(preview.at("/layout").isNull()).isTrue();
            assertThat(preview.at("/pairing")).as("nothing is paired before a layout is confirmed").isEmpty();
            assertThat(cell(preview, "C7").at("/text").asText()).isEqualTo("Every account belongs to one named person.");
            assertThat(cell(preview, "B2").at("/formula").asBoolean()).as("the date recalculated at every opening").isTrue();

            JsonNode values = read(mvc.perform(authenticated(get(BASE + "/release/versions/1/preview?sheet=Values"), importer))
                    .andExpect(status().isOk()));
            assertThat(cell(values, "A1").at("/text").asText()).isEqualTo("Done");
            assertThat(detailOf(mvc.perform(authenticated(get(BASE + "/release/versions/1/preview?sheet=Nowhere"), importer))
                    .andExpect(status().isBadRequest()).andReturn())).contains("\"Checklist\"");
        }

        @Test
        @DisplayName("reads the items by the confirmed layout, filled down, and counts the edit")
        void confirmingReadsTheItems() throws Exception {
            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated());

            JsonNode version = read(confirm(reviewer, "release", 1, layout(9)).andExpect(status().isOk()));

            assertThat(version.at("/version/layoutConfirmed").asBoolean()).isTrue();
            assertThat(version.at("/version/revision").asInt()).isEqualTo(2);
            assertThat(version.at("/version/itemCount").asLong()).isEqualTo(3);
            assertThat(version.at("/version/draftAuthors").toString())
                    .as("whoever confirmed the layout wrote the draft too")
                    .contains(importerName).contains(reviewerName);
            assertThat(version.at("/layout/answers/yes").asText()).isEqualTo("Done");
            assertThat(version.at("/items")).hasSize(3);
            JsonNode second = version.at("/items/1");
            assertThat(second.at("/domain").asText()).as("filled down").isEqualTo("Identity");
            assertThat(second.at("/objective").asText()).isEqualTo("1. Accounts are personal");
            assertThat(second.at("/control").asText()).isEqualTo("Shared accounts are disabled.");
            assertThat(second.at("/sheetRow").asInt()).isEqualTo(8);
            assertThat(second.at("/itemKey").asText()).startsWith("text:");
            assertThat(second.at("/evidenceKind").asText()).isEqualTo("none");
            assertThat(entries("CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED")).hasSize(1);
        }

        @Test
        @DisplayName("refuses a layout that cannot be one, in words (400)")
        void refusesALayoutThatIsNone() throws Exception {
            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated());

            Map<String, Object> noControl = layout(9);
            @SuppressWarnings("unchecked")
            Map<String, String> columns = new LinkedHashMap<>((Map<String, String>) noControl.get("columns"));
            columns.remove("control");
            noControl.put("columns", columns);
            assertThat(detailOf(confirm(importer, "release", 1, noControl).andExpect(status().isBadRequest()).andReturn()))
                    .contains("control");

            Map<String, Object> unknown = layout(9);
            unknown.put("columns", Map.of("control", "C", "answer", "F", "comment", "G", "owner", "H"));
            assertThat(detailOf(confirm(importer, "release", 1, unknown).andExpect(status().isBadRequest()).andReturn()))
                    .contains("\"owner\" is no column");

            Map<String, Object> badCell = layout(9);
            badCell.put("header", Map.of("date", Map.of("label", "A2", "value", "the cell beside")));
            assertThat(detailOf(confirm(importer, "release", 1, badCell).andExpect(status().isBadRequest()).andReturn()))
                    .contains("which is no cell");

            Map<String, Object> sameWords = layout(9);
            sameWords.put("answers", Map.of("yes", "Done", "no", " done "));
            confirm(importer, "release", 1, sameWords).andExpect(status().isBadRequest());

            Map<String, Object> noRows = layout(9);
            noRows.remove("lastItemRow");
            confirm(importer, "release", 1, noRows).andExpect(status().isBadRequest());

            Map<String, Object> otherSheet = layout(9);
            otherSheet.put("sheet", "Nowhere");
            confirm(importer, "release", 1, otherSheet).andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("publishing")
    class Publishing {

        @Test
        @DisplayName("with four-eyes on, the importer is refused and a second person publishes")
        void fourEyesCountsTwoPeople() throws Exception {
            exportTo("127.0.0.1:9");
            int revision = draftWithLayout("release");

            MvcResult refused = publish(importer, "release", 1, revision).andExpect(status().isConflict()).andReturn();
            assertThat(detailOf(refused)).contains("Four-eyes").contains(importerName);
            assertThat(statusOf("release", 1)).as("a refusal publishes nothing").isEqualTo("draft");
            assertThat(queued("CHECKLIST_TEMPLATE_CHANGED")).isEmpty();

            JsonNode published = read(publish(reviewer, "release", 1, revision).andExpect(status().isOk()));
            assertThat(published.at("/version/status").asText()).isEqualTo("published");
            assertThat(published.at("/version/publishedBy").asText()).isEqualTo(reviewerName);
            assertThat(published.at("/version/publishedAt").isNull()).isFalse();

            assertThat(entries("CHECKLIST_TEMPLATE_PUBLISHED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("four-eyes required"));
            assertThat(queued("CHECKLIST_TEMPLATE_CHANGED")).singleElement().satisfies(event -> {
                assertThat(event.at("/extensions/act").asText()).isEqualTo("CHECKLIST_TEMPLATE_PUBLISHED");
                assertThat(event.at("/extensions/suser").asText()).isEqualTo(reviewerName);
            });

            // Published is immutable: a change is a new version.
            confirm(reviewer, "release", 1, layout(9)).andExpect(status().isConflict());
            publish(reviewer, "release", 1, revision + 1).andExpect(status().isConflict());
        }

        @Test
        @DisplayName("with four-eyes on, whoever reshaped the draft is its author as much as its importer")
        void anEditorIsAnAuthor() throws Exception {
            int revision = draftWithLayout("release");
            // `draftWithLayout` confirmed as the importer; the reviewer confirms again and becomes an author.
            revision = read(confirm(reviewer, "release", 1, layout(9)).andExpect(status().isOk()))
                    .at("/version/revision").asInt();

            assertThat(detailOf(publish(reviewer, "release", 1, revision).andExpect(status().isConflict()).andReturn()))
                    .contains("Four-eyes");
            publish(asCiso(), "release", 1, revision).andExpect(status().isOk());
        }

        @Test
        @DisplayName("with four-eyes off, the importer publishes their own draft")
        void withoutFourEyesOnePersonSuffices() throws Exception {
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
            int revision = draftWithLayout("release");

            publish(importer, "release", 1, revision).andExpect(status().isOk());
            assertThat(entries("CHECKLIST_TEMPLATE_PUBLISHED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("four-eyes not required"));
        }

        @Test
        @DisplayName("refuses a draft whose layout nobody has confirmed")
        void refusesAnUnconfirmedDraft() throws Exception {
            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated());

            assertThat(detailOf(publish(reviewer, "release", 1, 1).andExpect(status().isConflict()).andReturn()))
                    .contains("no confirmed layout");
            assertThat(statusOf("release", 1)).isEqualTo("draft");
        }

        @Test
        @DisplayName("the statements themselves arbitrate: at a revision already moved on, none of them matches")
        void theStatementsArbitrate() throws Exception {
            // The service checks the revision before it writes, so the routes never reach a statement
            // with a stale one — except in the race between that check and the write, which is the
            // statement's alone to close. Asked directly, at the revision a writer read before an edit.
            int read = draftWithLayout("release");
            confirm(importer, "release", 1, layout(8)).andExpect(status().isOk());
            long id = version("release", 1).at("/version/id").asLong();
            Instant now = Instant.parse("2026-09-28T12:00:00Z");

            assertThat(versions.publish(id, read, "draft", "published", now, "late")).isZero();
            assertThat(versions.retire(id, read, "draft", "retired", now, "late")).isZero();
            assertThat(versions.editDraft(id, read, "draft", null, false, null, "[]")).isZero();
            assertThat(statusOf("release", 1)).isEqualTo("draft");

            // At the revision it is at, exactly one publication wins, and the second finds nothing.
            int current = version("release", 1).at("/version/revision").asInt();
            assertThat(versions.publish(id, current, "draft", "published", now, reviewerName)).isEqualTo(1);
            assertThat(versions.publish(id, current, "draft", "published", now, reviewerName)).isZero();
        }

        @Test
        @DisplayName("publishes the revision reviewed, and nothing edited after it")
        void refusesADraftEditedSinceTheReview() throws Exception {
            int reviewed = draftWithLayout("release");
            confirm(importer, "release", 1, layout(8)).andExpect(status().isOk());

            assertThat(detailOf(publish(reviewer, "release", 1, reviewed).andExpect(status().isConflict()).andReturn()))
                    .contains("has changed since revision " + reviewed);
            assertThat(detailOf(mvc.perform(authenticated(post(BASE + "/release/versions/1/publish"), reviewer)
                            .contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isBadRequest()).andReturn())).contains("revision");
            assertThat(statusOf("release", 1)).isEqualTo("draft");
        }

        @Test
        @DisplayName("an edit names the revision its editor read, so one lead's layout never silently replaces another's")
        void refusesAnEditOnAStaleRevision() throws Exception {
            // Both leads open revision `seen`; the importer confirms first.
            int seen = draftWithLayout("release");
            confirm(importer, "release", 1, layout(8), seen).andExpect(status().isOk());

            // The reviewer's layout and pairs were made on what they saw, which is no longer the draft.
            assertThat(detailOf(confirm(reviewer, "release", 1, layout(9), seen)
                    .andExpect(status().isConflict()).andReturn()))
                    .contains("has changed since revision " + seen);
            assertThat(detailOf(confirm(reviewer, "release", 1, layout(9), null)
                    .andExpect(status().isBadRequest()).andReturn()))
                    .contains("revision");
            assertThat(read(mvc.perform(authenticated(get(BASE + "/release/versions/1"), asAuditor()))
                    .andExpect(status().isOk())).at("/layout/lastItemRow").asInt())
                    .as("the importer's layout stands").isEqualTo(8);

            publish(reviewer, "release", 1, currentRevision("release", 1)).andExpect(status().isOk());
            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.SECOND), "").andExpect(status().isCreated());
            int second = read(confirm(importer, "release", 2, layout(10)).andExpect(status().isOk()))
                    .at("/version/revision").asInt();
            confirm(importer, "release", 2, layout(10), second).andExpect(status().isOk());
            assertThat(detailOf(pair(reviewer, "release", 2, List.of(), second)
                    .andExpect(status().isConflict()).andReturn()))
                    .contains("has changed since revision " + second);
            pair(reviewer, "release", 2, List.of(), null).andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("versions after the first")
    class Versions {

        @Test
        @DisplayName("an imported version pairs with the previous one, and a hand pair carries the old key")
        void pairingByHand() throws Exception {
            publishFirst("release");
            List<String> firstKeys = keys(version("release", 1));

            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.SECOND), "")
                    .andExpect(status().isCreated());
            assertThat(version("release", 2).at("/version/previousOrdinal").asInt()).isEqualTo(1);
            confirm(importer, "release", 2, layout(10)).andExpect(status().isOk());

            JsonNode pairing = preview("release", 2).at("/pairing");
            assertThat(changes(pairing)).containsExactly("unchanged", "added", "changed", "added", "removed");
            String reworded = pairing.get(1).at("/readKey").asText();
            String removed = pairing.get(4).at("/previousKey").asText();
            assertThat(removed).isEqualTo(firstKeys.get(1));

            JsonNode paired = read(pair(importer, "release", 2, List.of(Map.of("added", reworded, "removed", removed)))
                    .andExpect(status().isOk()));
            assertThat(paired.at("/items/1/itemKey").asText()).as("the new item takes the old key").isEqualTo(removed);
            assertThat(paired.at("/pairs/0/added").asText()).isEqualTo(reworded);

            JsonNode after = preview("release", 2).at("/pairing");
            assertThat(changes(after)).containsExactly("unchanged", "changed", "changed", "added");
            assertThat(after.get(1).at("/pairedByHand").asBoolean()).isTrue();
            assertThat(after.get(1).at("/readKey").asText()).isEqualTo(reworded);
            assertThat(after.get(2).at("/pairedByHand").asBoolean()).as("the KPI moved").isFalse();
            assertThat(entries("CHECKLIST_TEMPLATE_ITEMS_PAIRED")).hasSize(1);

            // A pair must join an added item with a removed one; an unchanged one is neither.
            assertThat(detailOf(pair(importer, "release", 2, List.of(Map.of("added", firstKeys.get(0), "removed", removed)))
                    .andExpect(status().isBadRequest()).andReturn())).contains("adds");
            assertThat(detailOf(pair(importer, "release", 2, List.of(Map.of("added", "row 8", "removed", removed)))
                    .andExpect(status().isBadRequest()).andReturn())).contains("\"text:");

            // A new layout reads the items anew; the pairs named items as the old one read them.
            JsonNode relaid = read(confirm(importer, "release", 2, layout(10)).andExpect(status().isOk()));
            assertThat(relaid.at("/pairs")).isEmpty();
            assertThat(relaid.at("/items/1/itemKey").asText()).isEqualTo(reworded);
        }

        @Test
        @DisplayName("the first version has nothing to pair with")
        void theFirstVersionPairsWithNothing() throws Exception {
            draftWithLayout("release");
            assertThat(changes(preview("release", 1).at("/pairing"))).containsOnly("added");
            assertThat(detailOf(pair(importer, "release", 1, List.of()).andExpect(status().isConflict()).andReturn()))
                    .contains("nothing to pair");
        }

        @Test
        @DisplayName("a version derived from a published one keeps its workbook, layout and keys, and pairs unchanged")
        void derivingKeepsEverything() throws Exception {
            publishFirst("release");
            JsonNode first = version("release", 1);

            JsonNode derived = read(mvc.perform(authenticated(post(BASE + "/release/versions/1/derive"), importer)
                            .contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"new bindings\"}"))
                    .andExpect(status().isCreated()));

            assertThat(derived.at("/version/ordinal").asInt()).isEqualTo(2);
            assertThat(derived.at("/version/status").asText()).isEqualTo("draft");
            assertThat(derived.at("/version/derivedFromOrdinal").asInt()).isEqualTo(1);
            assertThat(derived.at("/version/previousOrdinal").asInt()).isEqualTo(1);
            assertThat(derived.at("/version/label").asText()).isEqualTo("new bindings");
            assertThat(derived.at("/version/sourceSha256").asText()).isEqualTo(first.at("/version/sourceSha256").asText());
            assertThat(derived.at("/layout")).isEqualTo(first.at("/layout"));
            assertThat(keys(derived)).isEqualTo(keys(first));
            assertThat(changes(preview("release", 2).at("/pairing"))).containsOnly("unchanged");
            assertThat(entries("CHECKLIST_TEMPLATE_DERIVED")).hasSize(1);

            // One draft at a time, and a draft is edited rather than derived from.
            mvc.perform(authenticated(post(BASE + "/release/versions/1/derive"), importer))
                    .andExpect(status().isConflict());
            assertThat(detailOf(mvc.perform(authenticated(post(BASE + "/release/versions/2/derive"), importer))
                    .andExpect(status().isConflict()).andReturn())).contains("derived from a published one");
        }
    }

    @Nested
    @DisplayName("retiring")
    class Retiring {

        @Test
        @DisplayName("a published version, by somebody else when four-eyes is on, and it is the SIEM's event")
        void retiringAPublishedVersion() throws Exception {
            publishFirst("release");
            exportTo("127.0.0.1:9");

            assertThat(detailOf(mvc.perform(authenticated(post(BASE + "/release/versions/1/retire"), importer))
                    .andExpect(status().isConflict()).andReturn())).contains("Four-eyes");

            JsonNode retired = read(mvc.perform(authenticated(post(BASE + "/release/versions/1/retire"), reviewer))
                    .andExpect(status().isOk()));
            assertThat(retired.at("/version/status").asText()).isEqualTo("retired");
            assertThat(retired.at("/version/retiredBy").asText()).isEqualTo(reviewerName);
            assertThat(queued("CHECKLIST_TEMPLATE_CHANGED")).singleElement()
                    .satisfies(event -> assertThat(event.at("/extensions/act").asText()).isEqualTo("CHECKLIST_TEMPLATE_RETIRED"));

            mvc.perform(authenticated(post(BASE + "/release/versions/1/retire"), reviewer)).andExpect(status().isConflict());
            mvc.perform(authenticated(post(BASE + "/release/versions/1/derive"), reviewer)).andExpect(status().isConflict());
        }

        @Test
        @DisplayName("a draft set aside by its own author, which changes nothing any project attests to")
        void settingADraftAside() throws Exception {
            exportTo("127.0.0.1:9");
            importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated());

            mvc.perform(authenticated(post(BASE + "/release/versions/1/retire"), importer)).andExpect(status().isOk());

            assertThat(entries("CHECKLIST_TEMPLATE_RETIRED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("never published"));
            assertThat(queued("CHECKLIST_TEMPLATE_CHANGED")).isEmpty();
            // Set aside, it no longer holds the template's one draft.
            JsonNode next = read(importWorkbook(importer, "release", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated()));
            assertThat(next.at("/version/ordinal").asInt()).isEqualTo(2);
            assertThat(next.at("/version/previousOrdinal").isNull()).as("a draft set aside was never published").isTrue();
        }
    }

    @Nested
    @DisplayName("reading")
    class Reading {

        @Test
        @DisplayName("lists every template with its versions, to the governance readers only")
        void listing() throws Exception {
            publishFirst("release");
            importWorkbook(importer, "onboarding", ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "")
                    .andExpect(status().isCreated());

            JsonNode list = read(mvc.perform(authenticated(get(BASE), asAuditor())).andExpect(status().isOk()));
            assertThat(list).extracting(template -> template.at("/slug").asText()).containsExactly("onboarding", "release");
            assertThat(list.get(1).at("/versions/0/status").asText()).isEqualTo("published");
            assertThat(list.get(1).at("/versions/0/itemCount").asLong()).isEqualTo(3);

            mvc.perform(authenticated(get(BASE), asReader())).andExpect(status().isForbidden());
            mvc.perform(authenticated(get(BASE + "/release"), asSecurityChampion())).andExpect(status().isForbidden());
            mvc.perform(authenticated(get(BASE + "/release/versions/1"), asReader())).andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("answers an absent template or version 404, in words")
        void absent() throws Exception {
            assertThat(detailOf(mvc.perform(authenticated(get(BASE + "/nothing"), importer))
                    .andExpect(status().isNotFound()).andReturn())).contains("No checklist template \"nothing\"");
            draftWithLayout("release");
            assertThat(detailOf(mvc.perform(authenticated(get(BASE + "/release/versions/7"), importer))
                    .andExpect(status().isNotFound()).andReturn())).contains("has no version 7");
            publish(reviewer, "release", 7, 1).andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("the views cross the wire through the application's mapper, and a layout reads back as sent")
        void theWire() throws Exception {
            draftWithLayout("release");
            MvcResult result = mvc.perform(authenticated(get(BASE + "/release/versions/1"), importer))
                    .andExpect(status().isOk()).andReturn();

            // The application's own mapper, both ways: what the route sent is a view it reads back whole.
            ChecklistVersionView view = json.readValue(result.getResponse().getContentAsString(), ChecklistVersionView.class);
            assertThat(view.version().ordinal()).isEqualTo(1);
            assertThat(view.items()).hasSize(3);
            assertThat(view.layout().columns()).containsEntry("control", "C").containsEntry("answer", "F");
            assertThat(view.layout().header().get("date")).isEqualTo(new ChecklistLayoutForm.HeaderCellForm("A2", "B2"));
            assertThat(view.layout().answers().notApplicable()).isNull();
            assertThat(json.readTree(json.writeValueAsString(view))).isEqualTo(json.readTree(result.getResponse().getContentAsString()));

            // The layout the route shows is one the route takes: confirming it again changes no item.
            JsonNode again = read(confirm(importer, "release", 1, json.convertValue(view.layout(), Map.class))
                    .andExpect(status().isOk()));
            assertThat(keys(again)).isEqualTo(view.items().stream().map(item -> item.itemKey()).toList());
        }
    }

    // ------------------------------------------------------------------ helpers

    private ResultActions importWorkbook(String token, String slug, byte[] workbook, String query) throws Exception {
        return mvc.perform(authenticated(post(BASE + "/" + slug + "/versions" + query), token)
                .contentType(MediaType.APPLICATION_OCTET_STREAM).content(workbook));
    }

    /** Confirms a layout as a screen does: on the revision it has just read. */
    private ResultActions confirm(String token, String slug, int ordinal, Map<?, ?> layout) throws Exception {
        return confirm(token, slug, ordinal, layout, currentRevision(slug, ordinal));
    }

    private ResultActions confirm(String token, String slug, int ordinal, Map<?, ?> layout, Integer revision)
            throws Exception {
        var put = put(BASE + "/" + slug + "/versions/" + ordinal + "/layout");
        if (revision != null) {
            put = put.param("revision", String.valueOf(revision));
        }
        return mvc.perform(authenticated(put, token).contentType(MediaType.APPLICATION_JSON).content(write(layout)));
    }

    /** Pairs items as a screen does: on the revision it has just read. */
    private ResultActions pair(String token, String slug, int ordinal, List<Map<String, String>> pairs) throws Exception {
        return pair(token, slug, ordinal, pairs, currentRevision(slug, ordinal));
    }

    private ResultActions pair(String token, String slug, int ordinal, List<Map<String, String>> pairs, Integer revision)
            throws Exception {
        var put = put(BASE + "/" + slug + "/versions/" + ordinal + "/pairs");
        if (revision != null) {
            put = put.param("revision", String.valueOf(revision));
        }
        return mvc.perform(authenticated(put, token).contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of("pairs", pairs))));
    }

    /** The version's revision as a reader sees it now; absent for a version that does not exist. */
    private Integer currentRevision(String slug, int ordinal) throws Exception {
        MvcResult result = mvc.perform(authenticated(get(BASE + "/" + slug + "/versions/" + ordinal), asAuditor()))
                .andReturn();
        return result.getResponse().getStatus() == 200
                ? json.readTree(result.getResponse().getContentAsString()).at("/version/revision").asInt()
                : null;
    }

    private ResultActions publish(String token, String slug, int ordinal, int revision) throws Exception {
        return mvc.perform(authenticated(post(BASE + "/" + slug + "/versions/" + ordinal + "/publish"), token)
                .contentType(MediaType.APPLICATION_JSON).content("{\"revision\":" + revision + "}"));
    }

    /** The layout of {@link ChecklistWorkbooks}, its items ending on {@code lastItemRow}. */
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

    /** Imports the first workbook and confirms its layout as the importer; the draft's revision. */
    private int draftWithLayout(String slug) throws Exception {
        importWorkbook(importer, slug, ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST), "").andExpect(status().isCreated());
        return read(confirm(importer, slug, 1, layout(9)).andExpect(status().isOk())).at("/version/revision").asInt();
    }

    private void publishFirst(String slug) throws Exception {
        publish(reviewer, slug, 1, draftWithLayout(slug)).andExpect(status().isOk());
    }

    private JsonNode version(String slug, int ordinal) throws Exception {
        return read(mvc.perform(authenticated(get(BASE + "/" + slug + "/versions/" + ordinal), importer))
                .andExpect(status().isOk()));
    }

    private JsonNode preview(String slug, int ordinal) throws Exception {
        return read(mvc.perform(authenticated(get(BASE + "/" + slug + "/versions/" + ordinal + "/preview"), importer))
                .andExpect(status().isOk()));
    }

    private String statusOf(String slug, int ordinal) throws Exception {
        return version(slug, ordinal).at("/version/status").asText();
    }

    private static List<String> keys(JsonNode version) {
        List<String> keys = new ArrayList<>();
        version.at("/items").forEach(item -> keys.add(item.at("/itemKey").asText()));
        return keys;
    }

    private static List<String> changes(JsonNode pairing) {
        List<String> changes = new ArrayList<>();
        pairing.forEach(change -> changes.add(change.at("/change").asText()));
        return changes;
    }

    private static JsonNode cell(JsonNode preview, String reference) {
        for (JsonNode cell : preview.at("/cells")) {
            if (cell.at("/ref").asText().equals(reference)) {
                return cell;
            }
        }
        throw new AssertionError("no cell " + reference + " in the preview");
    }

    private JsonNode read(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
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

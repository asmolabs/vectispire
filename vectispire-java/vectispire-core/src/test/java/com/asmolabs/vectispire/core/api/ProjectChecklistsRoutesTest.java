package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistFileRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.LocalDate;
import java.time.ZoneOffset;
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
 * Project checklists through the real routes and the real filter chain (decision 0032 §4, §5, §8, §9):
 * opened on a published version, answered line by line with every answer kept, proven by links and
 * files, submitted, returned, signed off — by somebody who wrote none of it when four-eyes is on —
 * reopened and moved to the next version with the answers carried. Every route refuses a project the
 * caller does not see whole in the words of one that does not exist, and every write names the
 * edition its writer read.
 */
@DisplayName("project checklists, through the routes")
class ProjectChecklistsRoutesTest extends ApiTestBase {

    private static final String TEMPLATES = "/api/v1/checklist-templates";
    private static final String PROBLEM = "urn:vectispire:problem:";

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private UserRepository users;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ChecklistRepository checklists;

    @Autowired
    private ChecklistAnswerRepository answers;

    @Autowired
    private ChecklistEvidenceRepository evidence;

    @Autowired
    private ChecklistFileRepository files;

    @Autowired
    private ChecklistItemRepository items;

    /** An account the test acts as: its token, its identifier, its name. */
    private record Account(String token, long id, String name) {}

    private Account champion;
    private Account developer;
    private Account ciso;
    private long project;
    private long firstRepository;
    private long secondRepository;

    @BeforeEach
    void estate() throws Exception {
        // Templates are published with four-eyes off, so that a test switches it on for the sign-off alone.
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        publishTemplate("release", ChecklistWorkbooks.FIRST, 9);

        champion = account(Role.SECURITY_CHAMPION);
        developer = account(Role.USER);
        ciso = account(Role.CISO);

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

    // ------------------------------------------------------------------ who may see it

    @Nested
    @DisplayName("the whole project, or nothing")
    class Visibility {

        @Test
        @DisplayName("a reader who sees part of the project is answered as if it did not exist, on every route")
        void aPartialReaderIsAnsweredNotFound() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            long item = itemIds(read(developer, 1)).getFirst();
            restrict();
            Account partial = account(Role.USER);
            grant(partial.id(), "repository", firstRepository);

            // Every route, read and write, answers the one sentence an absent project gets.
            List<ResultActions> refused = List.of(
                    mvc.perform(authenticated(get(base()), partial.token())),
                    mvc.perform(authenticated(get(base() + "/offered"), partial.token())),
                    mvc.perform(authenticated(get(base() + "/1"), partial.token())),
                    mvc.perform(authenticated(get(base() + "/1/items/" + item + "/history"), partial.token())),
                    open(partial, "release", 1, 1),
                    answer(partial, 1, item, "yes", null, 1),
                    submit(partial, 1, 1));
            for (ResultActions result : refused) {
                MvcResult answered = result.andExpect(status().isNotFound()).andReturn();
                assertThat(detailOf(answered)).isEqualTo("Project not found.");
            }
            // The same words for a project that does not exist: nothing tells hidden from absent.
            assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/projects/" + (project + 1000) + "/checklists"),
                    partial.token())).andExpect(status().isNotFound()).andReturn())).isEqualTo("Project not found.");

            // Seeing both repositories is seeing the whole project, and so is the project granted as such.
            grant(partial.id(), "repository", secondRepository);
            mvc.perform(authenticated(get(base() + "/1"), partial.token())).andExpect(status().isOk());
            Account granted = account(Role.USER);
            grant(granted.id(), "project", project);
            mvc.perform(authenticated(get(base() + "/1"), granted.token())).andExpect(status().isOk());
        }

        @Test
        @DisplayName("an empty project is seen whole by its grantee and by nobody else: every one of none is not all")
        void anEmptyProjectIsNotVacuouslyVisible() throws Exception {
            long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Empty " + System.nanoTime()))))
                    .andExpect(status().isCreated()));
            long empty = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Later"))))
                    .andExpect(status().isCreated()));
            restrict();
            Account stranger = account(Role.USER);
            grant(stranger.id(), "repository", firstRepository);
            mvc.perform(authenticated(get("/api/v1/projects/" + empty + "/checklists"), stranger.token()))
                    .andExpect(status().isNotFound());

            Account grantee = account(Role.USER);
            grant(grantee.id(), "project", empty);
            mvc.perform(authenticated(get("/api/v1/projects/" + empty + "/checklists"), grantee.token()))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("reading is any account's, writing is not the auditor's nor the governor's, anonymity is nobody's")
        void theRoles() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            mvc.perform(authenticated(get(base() + "/1"), asAuditor())).andExpect(status().isOk());
            open(account(Role.AUDITOR), "release", 1, 1).andExpect(status().isForbidden());
            open(account(Role.SUPERUSER), "release", 1, 1).andExpect(status().isForbidden());
            mvc.perform(get(base())).andExpect(status().isUnauthorized());
        }
    }

    // ------------------------------------------------------------------ opening

    @Nested
    @DisplayName("opening a checklist")
    class Opening {

        @Test
        @DisplayName("opens a draft on a published version, its lines in the template's order, its header the caller's")
        void opensADraft() throws Exception {
            JsonNode opened = read(open(developer, "release", 1, null).andExpect(status().isCreated()));

            assertThat(opened.at("/checklist/revision").asInt()).isEqualTo(1);
            assertThat(opened.at("/checklist/status").asText()).isEqualTo("draft");
            assertThat(opened.at("/checklist/edition").asInt()).isEqualTo(1);
            assertThat(opened.at("/checklist/templateSlug").asText()).isEqualTo("release");
            assertThat(opened.at("/checklist/versionOrdinal").asInt()).isEqualTo(1);
            assertThat(opened.at("/checklist/author").asText()).isEqualTo(developer.name());
            assertThat(opened.at("/projectName").asText()).isEqualTo("Checkout");
            assertThat(opened.at("/answerWords/yes").asText()).isEqualTo("Done");
            assertThat(opened.at("/answerWords/notApplicable").isNull()).isTrue();
            assertThat(opened.at("/lines")).hasSize(3);
            assertThat(opened.at("/lines/0/control").asText()).isEqualTo("Every account belongs to one named person.");
            assertThat(opened.at("/lines/1/domain").asText()).as("filled down").isEqualTo("Identity");
            assertThat(opened.at("/lines/0/problems").toString()).isEqualTo("[\"unanswered\"]");
            assertThat(opened.at("/readyToSubmit").asBoolean()).isFalse();

            assertThat(entries("CHECKLIST_OPENED")).singleElement().satisfies(entry -> {
                assertThat(entry.getUserId()).isEqualTo(developer.name());
                assertThat(entry.getResourceId()).isEqualTo(project + "/1");
            });
            assertThat(read(mvc.perform(authenticated(get(base()), developer.token())).andExpect(status().isOk())))
                    .hasSize(1);
            assertThat(read(mvc.perform(authenticated(get(base() + "/offered"), developer.token()))
                    .andExpect(status().isOk())).at("/0/templateSlug").asText()).isEqualTo("release");
        }

        @Test
        @DisplayName("refuses a second open by whoever saw no checklist, a version not published, and what names none")
        void refusals() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());

            MvcResult second = open(champion, "release", 1, null).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(second)).isEqualTo(PROBLEM + "checklist-changed");
            assertThat(typeOf(open(champion, "release", 1, 1).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-same-version");

            importDraft("release", ChecklistWorkbooks.SECOND, 10);
            assertThat(typeOf(open(champion, "release", 2, 1).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-version-not-published");
            assertThat(detailOf(open(champion, "nowhere", 1, 1).andExpect(status().isNotFound()).andReturn()))
                    .contains("No checklist template");
            mvc.perform(authenticated(post(base()), champion.token()).contentType(MediaType.APPLICATION_JSON)
                    .content("{}")).andExpect(status().isBadRequest());
            assertThat(checklists.findByProjectIdOrderByRevisionDesc(project)).hasSize(1);
        }

        @Test
        @DisplayName("the open-slot key keeps a project to one open checklist, whatever the service believed")
        void oneOpenChecklist() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            var open = checklists.findByProjectIdAndRevision(project, 1).orElseThrow();
            var twin = new com.asmolabs.vectispire.core.checklists.persistence.ChecklistEntity();
            twin.setProjectId(project);
            twin.setTemplateVersionId(open.getTemplateVersionId());
            twin.setRevision(2);
            twin.setStatus("draft");
            twin.setEdition(1);
            twin.setOpenSlot(1);
            twin.setAuthorId(developer.id());
            twin.setAuthor(developer.name());
            twin.setOpenedAt(open.getOpenedAt());
            twin.setOpenedBy(developer.name());
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> checklists.saveAndFlush(twin))
                    .isInstanceOf(RuntimeException.class);
        }
    }

    // ------------------------------------------------------------------ answering

    @Nested
    @DisplayName("answering")
    class Answering {

        @Test
        @DisplayName("every answer is a new row: the history keeps each with its author, the newest is current")
        void historyIsAppendOnly() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            long item = itemIds(read(developer, 1)).getFirst();

            answer(developer, 1, item, "no", "Two service accounts remain.", edition(1)).andExpect(status().isCreated());
            answer(champion, 1, item, "yes", null, edition(1)).andExpect(status().isCreated());

            JsonNode line = read(developer, 1).at("/lines/0");
            assertThat(line.at("/answer/value").asText()).isEqualTo("yes");
            assertThat(line.at("/answer/answeredBy").asText()).isEqualTo(champion.name());
            JsonNode history = read(mvc.perform(authenticated(get(base() + "/1/items/" + item + "/history"), asAuditor()))
                    .andExpect(status().isOk()));
            assertThat(history.at("/answers")).hasSize(2);
            assertThat(history.at("/answers/0/value").asText()).isEqualTo("no");
            assertThat(history.at("/answers/0/comment").asText()).isEqualTo("Two service accounts remain.");
            assertThat(history.at("/answers/0/answeredBy").asText()).isEqualTo(developer.name());
            assertThat(history.at("/answers/0/answeredAt").asText()).as("an instant, as the real mapper writes one")
                    .matches("\\d{4}-\\d{2}-\\d{2}T.*Z");
            assertThat(history.at("/answers/1/answeredBy").asText()).isEqualTo(champion.name());
            // The first answer is still in the table as it was written: nothing updated it.
            assertThat(answers.findAll()).hasSize(2)
                    .anySatisfy(row -> assertThat(row.getComment()).isEqualTo("Two service accounts remain."));
            assertThat(entries("CHECKLIST_ANSWERED")).hasSize(2);
        }

        @Test
        @DisplayName("refuses a negative answer without its comment, an answer that is none, and not applicable where not offered")
        void refusesWhatIsNoAnswer() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            long item = itemIds(read(developer, 1)).getFirst();

            assertThat(detailOf(answer(developer, 1, item, "no", " ", 1).andExpect(status().isBadRequest()).andReturn()))
                    .contains("needs a comment");
            assertThat(detailOf(answer(developer, 1, item, "maybe", null, 1).andExpect(status().isBadRequest())
                    .andReturn())).contains("An answer is one of");
            assertThat(detailOf(answer(developer, 1, item, "not_applicable", "Not our scope.", 1)
                    .andExpect(status().isBadRequest()).andReturn())).contains("does not offer");
            answer(developer, 1, item + 10_000, "yes", null, 1).andExpect(status().isNotFound());
            assertThat(answers.findAll()).isEmpty();
        }

        @Test
        @DisplayName("names the edition read: absent is 400, a line changed since is 409, another line changed is not")
        void theEditionRead() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            List<Long> lines = itemIds(read(developer, 1));

            assertThat(detailOf(answer(developer, 1, lines.get(0), "yes", null, null).andExpect(status().isBadRequest())
                    .andReturn())).contains("edition");

            // Both read edition 1. The champion answers line 1; the developer's answer to the same line,
            // from the same screen, would replace it unseen — refused. Line 2 moved nobody's work: taken.
            answer(champion, 1, lines.get(0), "yes", null, 1).andExpect(status().isCreated());
            MvcResult stale = answer(developer, 1, lines.get(0), "no", "Not yet.", 1).andExpect(status().isConflict())
                    .andReturn();
            assertThat(typeOf(stale)).isEqualTo(PROBLEM + "checklist-line-changed");
            answer(developer, 1, lines.get(1), "yes", null, 1).andExpect(status().isCreated());

            assertThat(read(developer, 1).at("/lines/0/answer/answeredBy").asText())
                    .as("the champion's answer stands").isEqualTo(champion.name());
            assertThat(typeOf(answer(developer, 1, lines.get(2), "yes", null, 99).andExpect(status().isConflict())
                    .andReturn())).as("an edition not reached yet").isEqualTo(PROBLEM + "checklist-changed");
        }
    }

    // ------------------------------------------------------------------ proofs

    @Nested
    @DisplayName("proofs")
    class Proofs {

        @Test
        @DisplayName("a file goes back only as an attachment, opaque and unsniffed, byte for byte")
        void aFileIsADownload() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            long item = itemIds(read(developer, 1)).getFirst();
            byte[] html = "<html><script>alert(document.cookie)</script></html>".getBytes();

            JsonNode view = read(attachFile(developer, 1, item, "../../report.html", "text/html", html, edition(1))
                    .andExpect(status().isCreated()));
            JsonNode proof = view.at("/lines/0/evidence/0");
            assertThat(proof.at("/kind").asText()).isEqualTo("file");
            assertThat(proof.at("/fileName").asText()).as("a name, never a path").isEqualTo("report.html");
            assertThat(proof.at("/mediaType").asText()).isEqualTo("text/html");
            assertThat(proof.at("/fileSha256").asText()).isEqualTo(Digests.sha256Hex(html));
            assertThat(proof.at("/performedOn").asText()).as("a day, as the real mapper writes one")
                    .isEqualTo(today().toString());

            MvcResult download = mvc.perform(authenticated(
                            get(base() + "/1/evidence/" + proof.at("/id").asLong() + "/file"), asAuditor()))
                    .andExpect(status().isOk()).andReturn();
            assertThat(download.getResponse().getHeader("Content-Disposition")).startsWith("attachment;")
                    .contains("report.html");
            assertThat(download.getResponse().getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
            assertThat(download.getResponse().getContentType()).isEqualTo("application/octet-stream");
            assertThat(download.getResponse().getContentAsByteArray()).isEqualTo(html);
            assertThat(entries("CHECKLIST_EVIDENCE_ADDED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains(Digests.sha256Hex(html)));
        }

        @Test
        @DisplayName("a file past the ceiling is refused before it is read (413), an empty one in words (400)")
        void aFileIsBounded() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            long item = itemIds(read(developer, 1)).getFirst();

            MvcResult tooLarge = attachFile(developer, 1, item, "big.pdf", "application/pdf",
                    new byte[25 * 1024 * 1024 + 1], 1).andExpect(status().is(413)).andReturn();
            assertThat(detailOf(tooLarge)).contains("26214400 bytes");
            attachFile(developer, 1, item, "empty.pdf", "application/pdf", new byte[0], 1)
                    .andExpect(status().isBadRequest());
            assertThat(files.findAll()).isEmpty();
        }

        @Test
        @DisplayName("a link is an https or http address, of work done by today; withdrawn, it is kept and dated")
        void linksAndWithdrawal() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            long item = itemIds(read(developer, 1)).getFirst();

            attachLink(developer, 1, item, "javascript:alert(1)", today().toString(), 1).andExpect(status().isBadRequest());
            attachLink(developer, 1, item, "https://wiki.example.invalid/pentest", today().plusDays(1).toString(), 1)
                    .andExpect(status().isBadRequest());
            attachLink(developer, 1, item, "https://wiki.example.invalid/pentest", "28/09/2026", 1)
                    .andExpect(status().isBadRequest());
            JsonNode view = read(attachLink(developer, 1, item, "https://wiki.example.invalid/pentest", today().toString(), 1)
                    .andExpect(status().isCreated()));
            long proof = view.at("/lines/0/evidence/0/id").asLong();

            JsonNode withdrawn = read(send(champion, base() + "/1/evidence/" + proof + "/withdrawal",
                    Map.of("edition", edition(1))).andExpect(status().isOk()));
            assertThat(withdrawn.at("/lines/0/evidence/0/withdrawnBy").asText()).isEqualTo(champion.name());
            assertThat(withdrawn.at("/lines/0/evidence/0/inDate").asBoolean()).isFalse();
            assertThat(typeOf(send(champion, base() + "/1/evidence/" + proof + "/withdrawal", Map.of("edition", edition(1)))
                    .andExpect(status().isConflict()).andReturn())).isEqualTo(PROBLEM + "checklist-evidence-withdrawn");
            assertThat(evidence.findAll()).singleElement().satisfies(row -> assertThat(row.getWithdrawnAt()).isNotNull());
            assertThat(entries("CHECKLIST_EVIDENCE_WITHDRAWN")).hasSize(1);
        }

        @Test
        @DisplayName("a yes on a line asking for a file is submitted with one in date, never with a link or a lapsed one")
        void theEvidenceRequirement() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            List<Long> lines = itemIds(read(developer, 1));
            // No route binds an evidence requirement yet (the rules' lot will): set on the stored item.
            ChecklistItemEntity asksAFile = items.findById(lines.getFirst()).orElseThrow();
            asksAFile.setEvidenceKind("file");
            asksAFile.setEvidenceValidityMonths(1);
            items.save(asksAFile);
            answerAll(developer, 1, lines);

            attachLink(developer, 1, lines.getFirst(), "https://wiki.example.invalid/review", today().toString(), edition(1))
                    .andExpect(status().isCreated());
            MvcResult withALink = submit(developer, 1, edition(1)).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(withALink)).isEqualTo(PROBLEM + "checklist-incomplete");
            assertThat(detailOf(withALink)).contains("line 1 evidence required");

            attachFile(developer, 1, lines.getFirst(), "old.pdf", "application/pdf", new byte[] {1},
                    today().minusMonths(2).toString(), edition(1)).andExpect(status().isCreated());
            assertThat(detailOf(submit(developer, 1, edition(1)).andExpect(status().isConflict()).andReturn()))
                    .contains("line 1 evidence expired");

            attachFile(developer, 1, lines.getFirst(), "new.pdf", "application/pdf", new byte[] {2}, today().toString(),
                    edition(1)).andExpect(status().isCreated());
            submit(developer, 1, edition(1)).andExpect(status().isOk());
        }
    }

    // ------------------------------------------------------------------ submitting, returning, signing off

    @Nested
    @DisplayName("submitting and signing off")
    class SigningOff {

        @Test
        @DisplayName("a submission names the edition reviewed and every line; a submitted revision is not answered")
        void submitting() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            List<Long> lines = itemIds(read(developer, 1));
            answer(developer, 1, lines.get(0), "yes", null, edition(1)).andExpect(status().isCreated());

            MvcResult incomplete = submit(developer, 1, edition(1)).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(incomplete)).isEqualTo(PROBLEM + "checklist-incomplete");
            assertThat(detailOf(incomplete)).contains("line 2 unanswered").contains("line 3 unanswered");

            answer(developer, 1, lines.get(1), "no", "Two service accounts remain.", edition(1)).andExpect(status().isCreated());
            answer(developer, 1, lines.get(2), "yes", null, edition(1)).andExpect(status().isCreated());
            int reviewed = edition(1);
            submit(developer, 1, null).andExpect(status().isBadRequest());
            assertThat(typeOf(submit(developer, 1, reviewed - 1).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-changed");

            JsonNode submitted = read(submit(developer, 1, reviewed).andExpect(status().isOk()));
            assertThat(submitted.at("/checklist/status").asText()).isEqualTo("submitted");
            assertThat(submitted.at("/checklist/submittedBy").asText()).isEqualTo(developer.name());
            assertThat(typeOf(answer(developer, 1, lines.get(0), "no", "Changed my mind.", edition(1))
                    .andExpect(status().isConflict()).andReturn())).isEqualTo(PROBLEM + "checklist-not-draft");
            assertThat(typeOf(submit(developer, 1, edition(1)).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-not-draft");
            assertThat(entries("CHECKLIST_SUBMITTED")).hasSize(1);
        }

        @Test
        @DisplayName("with four-eyes on, an author is refused and signalled, and a second approver signs off")
        void fourEyesCountsTwoPeople() throws Exception {
            exportTo("127.0.0.1:9");
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
            // The champion opens and answers one line; the developer answers the rest and submits.
            open(champion, "release", 1, null).andExpect(status().isCreated());
            List<Long> lines = itemIds(read(developer, 1));
            answer(champion, 1, lines.get(0), "yes", null, edition(1)).andExpect(status().isCreated());
            answer(developer, 1, lines.get(1), "yes", null, edition(1)).andExpect(status().isCreated());
            answer(developer, 1, lines.get(2), "yes", null, edition(1)).andExpect(status().isCreated());
            submit(developer, 1, edition(1)).andExpect(status().isOk());

            // An approver who answered a line is one of its authors, not only the submitter.
            MvcResult refused = signOff(champion, 1, edition(1)).andExpect(status().isConflict()).andReturn();
            assertThat(typeOf(refused)).isEqualTo(PROBLEM + "checklist-four-eyes");
            assertThat(detailOf(refused)).contains("Four-eyes").contains(champion.name());
            assertThat(read(developer, 1).at("/checklist/status").asText()).as("a refusal signs nothing off")
                    .isEqualTo("submitted");
            assertThat(entries("CHECKLIST_SIGN_OFF_REFUSED")).singleElement()
                    .satisfies(entry -> assertThat(entry.getUserId()).isEqualTo(champion.name()));
            assertThat(queued("CHECKLIST_SIGN_OFF_REFUSED")).singleElement()
                    .satisfies(event -> assertThat(event.at("/extensions/act").asText()).isEqualTo("CHECKLIST_SIGN_OFF_REFUSED"));

            JsonNode signed = read(signOff(ciso, 1, edition(1)).andExpect(status().isOk()));
            assertThat(signed.at("/checklist/status").asText()).isEqualTo("signed_off");
            assertThat(signed.at("/checklist/signedOffBy").asText()).isEqualTo(ciso.name());
            assertThat(signed.at("/checklist/signOffFourEyes").asBoolean()).isTrue();
            assertThat(entries("CHECKLIST_SIGNED_OFF")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("four-eyes required"));
            assertThat(queued("CHECKLIST_SIGNED_OFF")).singleElement()
                    .satisfies(event -> assertThat(event.at("/extensions/suser").asText()).isEqualTo(ciso.name()));
            assertThat(typeOf(signOff(asCisoAccount(), 1, edition(1)).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-not-submitted");
        }

        @Test
        @DisplayName("the submitter is refused too, and with four-eyes off the author may sign what they wrote")
        void theSubmitterAndTheSettingOff() throws Exception {
            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
            open(developer, "release", 1, null).andExpect(status().isCreated());
            answerAll(developer, 1, itemIds(read(developer, 1)));
            submit(champion, 1, edition(1)).andExpect(status().isOk());
            assertThat(typeOf(signOff(champion, 1, edition(1)).andExpect(status().isConflict()).andReturn()))
                    .as("the submitter").isEqualTo(PROBLEM + "checklist-four-eyes");

            settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
            JsonNode signed = read(signOff(champion, 1, edition(1)).andExpect(status().isOk()));
            assertThat(signed.at("/checklist/signOffFourEyes").asBoolean()).isFalse();
        }

        @Test
        @DisplayName("signing off is an approver's: a developer is refused 403, and the edition read is named")
        void onlyAnApproverSigns() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            answerAll(developer, 1, itemIds(read(developer, 1)));
            submit(developer, 1, edition(1)).andExpect(status().isOk());

            signOff(developer, 1, edition(1)).andExpect(status().isForbidden());
            signOff(ciso, 1, null).andExpect(status().isBadRequest());
            assertThat(typeOf(signOff(ciso, 1, edition(1) - 1).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-changed");
        }

        @Test
        @DisplayName("a submitted revision returned with its reason is a draft again, and signalled")
        void returning() throws Exception {
            exportTo("127.0.0.1:9");
            open(developer, "release", 1, null).andExpect(status().isCreated());
            answerAll(developer, 1, itemIds(read(developer, 1)));
            submit(developer, 1, edition(1)).andExpect(status().isOk());

            send(ciso, base() + "/1/return", Map.of("edition", edition(1))).andExpect(status().isBadRequest());
            JsonNode returned = read(send(ciso, base() + "/1/return",
                    Map.of("edition", edition(1), "reason", "Line 2 needs the directory export.")).andExpect(status().isOk()));
            assertThat(returned.at("/checklist/status").asText()).isEqualTo("draft");
            assertThat(returned.at("/checklist/returnReason").asText()).isEqualTo("Line 2 needs the directory export.");
            assertThat(returned.at("/checklist/returnedBy").asText()).isEqualTo(ciso.name());
            assertThat(typeOf(send(ciso, base() + "/1/return", Map.of("edition", edition(1), "reason", "Again."))
                    .andExpect(status().isConflict()).andReturn())).isEqualTo(PROBLEM + "checklist-not-submitted");
            assertThat(queued("CHECKLIST_SIGN_OFF_REFUSED")).singleElement()
                    .satisfies(event -> assertThat(event.at("/extensions/act").asText()).isEqualTo("CHECKLIST_RETURNED"));
        }
    }

    // ------------------------------------------------------------------ reopening and moving

    @Nested
    @DisplayName("reopening and moving to another version")
    class Carrying {

        @Test
        @DisplayName("reopening a signed-off revision opens the next with every answer current; the signed one is untouched")
        void reopening() throws Exception {
            signedOffRevisionOne();
            int signedEdition = edition(1);

            JsonNode reopened = read(send(champion, base() + "/1/reopen", Map.of("edition", signedEdition))
                    .andExpect(status().isCreated()));
            assertThat(reopened.at("/checklist/revision").asInt()).isEqualTo(2);
            assertThat(reopened.at("/checklist/status").asText()).isEqualTo("draft");
            assertThat(reopened.at("/checklist/supersedesRevision").asInt()).isEqualTo(1);
            JsonNode line = reopened.at("/lines/0/answer");
            assertThat(line.at("/answeredBy").asText()).as("the answer stays its author's").isEqualTo(developer.name());
            assertThat(line.at("/carriedBy").asText()).isEqualTo(champion.name());
            assertThat(line.at("/needsConfirmation").asBoolean()).isFalse();
            assertThat(reopened.at("/readyToSubmit").asBoolean()).isTrue();

            JsonNode signed = read(developer, 1);
            assertThat(signed.at("/checklist/status").asText()).isEqualTo("signed_off");
            assertThat(signed.at("/checklist/edition").asInt()).isEqualTo(signedEdition);
            assertThat(typeOf(send(champion, base() + "/1/reopen", Map.of("edition", signedEdition))
                    .andExpect(status().isConflict()).andReturn())).isEqualTo(PROBLEM + "checklist-not-latest");
            assertThat(typeOf(send(champion, base() + "/2/reopen", Map.of("edition", edition(2)))
                    .andExpect(status().isConflict()).andReturn())).isEqualTo(PROBLEM + "checklist-not-signed-off");
            assertThat(entries("CHECKLIST_REOPENED")).hasSize(1);
        }

        @Test
        @DisplayName("across two versions: unchanged lines carried as current, changed and paired ones to be confirmed")
        void movingAcrossTwoVersions() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            List<Long> first = itemIds(read(developer, 1));
            answer(developer, 1, first.get(0), "yes", null, edition(1)).andExpect(status().isCreated());
            answer(developer, 1, first.get(1), "no", "Two service accounts remain.", edition(1)).andExpect(status().isCreated());
            answer(developer, 1, first.get(2), "yes", null, edition(1)).andExpect(status().isCreated());
            attachLink(developer, 1, first.get(0), "https://wiki.example.invalid/accounts", today().toString(), edition(1))
                    .andExpect(status().isCreated());

            // Version 2 rewords line 2 — paired by hand with the old one — moves line 3's KPI, adds a fourth.
            importDraft("release", ChecklistWorkbooks.SECOND, 10);
            JsonNode pairing = read(mvc.perform(authenticated(get(TEMPLATES + "/release/versions/2/preview"), asAdmin()))
                    .andExpect(status().isOk())).at("/pairing");
            String reworded = pairing.get(1).at("/readKey").asText();
            String removed = pairing.get(4).at("/previousKey").asText();
            mvc.perform(authenticated(put(TEMPLATES + "/release/versions/2/pairs"), asAdmin())
                            .param("revision", String.valueOf(templateRevision("release", 2)))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("pairs", List.of(Map.of("added", reworded, "removed", removed))))))
                    .andExpect(status().isOk());
            publish("release", 2);

            JsonNode moved = read(open(champion, "release", 2, edition(1)).andExpect(status().isCreated()));
            assertThat(moved.at("/checklist/revision").asInt()).isEqualTo(2);
            assertThat(moved.at("/checklist/versionOrdinal").asInt()).isEqualTo(2);
            assertThat(moved.at("/lines")).hasSize(4);
            assertThat(moved.at("/lines/0/answer/needsConfirmation").asBoolean()).as("unchanged: current").isFalse();
            assertThat(moved.at("/lines/0/answer/answeredBy").asText()).isEqualTo(developer.name());
            assertThat(moved.at("/lines/0/evidence")).as("its proof follows it").hasSize(1);
            assertThat(moved.at("/lines/1/answer/needsConfirmation").asBoolean()).as("paired by hand").isTrue();
            assertThat(moved.at("/lines/1/answer/comment").asText()).isEqualTo("Two service accounts remain.");
            assertThat(moved.at("/lines/2/answer/needsConfirmation").asBoolean()).as("the KPI moved").isTrue();
            assertThat(moved.at("/lines/3/answer").isNull()).as("added: unanswered").isTrue();
            assertThat(read(developer, 1).at("/checklist/status").asText()).isEqualTo("superseded");
            assertThat(entries("CHECKLIST_MOVED_TO_VERSION")).singleElement()
                    .satisfies(entry -> assertThat(entry.getDescription()).contains("1 answer carried as current, 2 to be confirmed"));

            // Never silently current: the revision is not submitted until somebody confirms or answers.
            List<Long> second = itemIds(moved);
            answer(champion, 2, second.get(3), "yes", null, edition(2)).andExpect(status().isCreated());
            assertThat(detailOf(submit(champion, 2, edition(2)).andExpect(status().isConflict()).andReturn()))
                    .contains("line 2 awaiting confirmation").contains("line 3 awaiting confirmation");
            assertThat(typeOf(send(champion, base() + "/2/items/" + second.get(0) + "/confirmation",
                    Map.of("edition", edition(2))).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-nothing-to-confirm");
            JsonNode confirmed = read(send(champion, base() + "/2/items/" + second.get(1) + "/confirmation",
                    Map.of("edition", edition(2))).andExpect(status().isCreated()));
            assertThat(confirmed.at("/lines/1/answer/answeredBy").asText()).isEqualTo(champion.name());
            assertThat(confirmed.at("/lines/1/answer/needsConfirmation").asBoolean()).isFalse();
            answer(champion, 2, second.get(2), "yes", null, edition(2)).andExpect(status().isCreated());
            submit(champion, 2, edition(2)).andExpect(status().isOk());

            // And on to a third version derived from the second: every line unchanged, every answer current,
            // each copy pointing at the row it came from.
            mvc.perform(authenticated(post(TEMPLATES + "/release/versions/2/derive"), asAdmin())).andExpect(status().isCreated());
            publish("release", 3);
            JsonNode third = read(open(developer, "release", 3, edition(2)).andExpect(status().isCreated()));
            assertThat(third.at("/checklist/revision").asInt()).isEqualTo(3);
            for (JsonNode line : third.at("/lines")) {
                assertThat(line.at("/answer/needsConfirmation").asBoolean()).isFalse();
                assertThat(line.at("/answer/carriedFromId").isNull()).isFalse();
            }
            assertThat(third.at("/readyToSubmit").asBoolean()).isTrue();
            assertThat(read(developer, 2).at("/checklist/status").asText()).as("a submitted revision is superseded too")
                    .isEqualTo("superseded");
        }

        @Test
        @DisplayName("a move names the edition of the revision read: another's write since is refused")
        void aMoveNamesTheEditionRead() throws Exception {
            open(developer, "release", 1, null).andExpect(status().isCreated());
            importDraft("release", ChecklistWorkbooks.SECOND, 10);
            publish("release", 2);
            answer(champion, 1, itemIds(read(developer, 1)).getFirst(), "yes", null, 1).andExpect(status().isCreated());

            assertThat(typeOf(open(developer, "release", 2, 1).andExpect(status().isConflict()).andReturn()))
                    .isEqualTo(PROBLEM + "checklist-changed");
            assertThat(checklists.findByProjectIdOrderByRevisionDesc(project)).hasSize(1);
        }
    }

    // ------------------------------------------------------------------ deleting the project

    @Test
    @DisplayName("deleting the project takes its checklists, answers, proofs and files with it, and leaves the audit trail")
    void deletingTheProjectPurges() throws Exception {
        open(developer, "release", 1, null).andExpect(status().isCreated());
        long item = itemIds(read(developer, 1)).getFirst();
        answer(developer, 1, item, "yes", null, edition(1)).andExpect(status().isCreated());
        attachFile(developer, 1, item, "proof.pdf", "application/pdf", new byte[] {1, 2, 3}, edition(1))
                .andExpect(status().isCreated());
        attachLink(developer, 1, item, "https://wiki.example.invalid/proof", today().toString(), edition(1))
                .andExpect(status().isCreated());

        mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());

        assertThat(checklists.findAll()).isEmpty();
        assertThat(answers.findAll()).isEmpty();
        assertThat(evidence.findAll()).isEmpty();
        assertThat(files.findAll()).isEmpty();
        assertThat(entries("CHECKLIST_OPENED")).hasSize(1);
        assertThat(entries("CHECKLIST_ANSWERED")).hasSize(1);
    }

    // ------------------------------------------------------------------ helpers

    private String base() {
        return "/api/v1/projects/" + project + "/checklists";
    }

    private Account account(Role role) {
        String name = role.name().toLowerCase(java.util.Locale.ROOT) + "-" + System.nanoTime();
        String token = tokenFor(name, role, false);
        return new Account(token, users.findByUsername(name).orElseThrow().getId(), name);
    }

    private Account asCisoAccount() {
        return account(Role.CISO);
    }

    private static LocalDate today() {
        return LocalDate.now(ZoneOffset.UTC);
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

    private void restrict() {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
    }

    private void grant(long userId, String kind, long id) throws Exception {
        // The grants a user already holds stay: the route replaces the whole list.
        List<Map<String, Object>> held = new ArrayList<>();
        read(mvc.perform(authenticated(get("/api/v1/users/" + userId + "/targets"), asAdmin())).andExpect(status().isOk()))
                .forEach(grant -> held.add(Map.of("kind", grant.at("/kind").asText(), "id", grant.at("/id").asLong())));
        held.add(Map.of("kind", kind, "id", id));
        mvc.perform(authenticated(put("/api/v1/users/" + userId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(held)))
                .andExpect(status().isOk());
    }

    /** Imports a workbook as the template's next version and confirms its layout, as an administrator. */
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

    private void publishTemplate(String slug, List<ChecklistWorkbooks.Line> lines, int lastItemRow) throws Exception {
        importDraft(slug, lines, lastItemRow);
        publish(slug, 1);
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

    private ResultActions open(Account who, String slug, int version, Integer edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", slug);
        body.put("version", version);
        body.put("edition", edition);
        return send(who, base(), body);
    }

    private ResultActions answer(Account who, int revision, long item, String value, String comment, Integer edition)
            throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value);
        body.put("comment", comment);
        body.put("edition", edition);
        return send(who, base() + "/" + revision + "/items/" + item + "/answers", body);
    }

    /** Answers every line yes, each at the edition just read. */
    private void answerAll(Account who, int revision, List<Long> lines) throws Exception {
        for (long line : lines) {
            answer(who, revision, line, "yes", null, edition(revision)).andExpect(status().isCreated());
        }
    }

    private ResultActions attachLink(Account who, int revision, long item, String link, String performedOn, Integer edition)
            throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("link", link);
        body.put("performedOn", performedOn);
        body.put("edition", edition);
        return send(who, base() + "/" + revision + "/items/" + item + "/evidence/links", body);
    }

    private ResultActions attachFile(Account who, int revision, long item, String name, String type, byte[] content,
            Integer edition) throws Exception {
        return attachFile(who, revision, item, name, type, content, today().toString(), edition);
    }

    private ResultActions attachFile(Account who, int revision, long item, String name, String type, byte[] content,
            String performedOn, Integer edition) throws Exception {
        var request = post(base() + "/" + revision + "/items/" + item + "/evidence/files")
                .param("name", name).param("performedOn", performedOn).contentType(type).content(content);
        if (edition != null) {
            request = request.param("edition", String.valueOf(edition));
        }
        return mvc.perform(authenticated(request, who.token()));
    }

    private ResultActions submit(Account who, int revision, Integer edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("edition", edition);
        return send(who, base() + "/" + revision + "/submission", body);
    }

    private ResultActions signOff(Account who, int revision, Integer edition) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("edition", edition);
        return send(who, base() + "/" + revision + "/sign-off", body);
    }

    private ResultActions send(Account who, String path, Map<String, ?> body) throws Exception {
        return mvc.perform(authenticated(
                post(path), who.token())
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    /** Revision one answered by the developer, submitted by them, signed off by the CISO. */
    private void signedOffRevisionOne() throws Exception {
        open(developer, "release", 1, null).andExpect(status().isCreated());
        answerAll(developer, 1, itemIds(read(developer, 1)));
        submit(developer, 1, edition(1)).andExpect(status().isOk());
        signOff(ciso, 1, edition(1)).andExpect(status().isOk());
    }

    private JsonNode read(Account who, int revision) throws Exception {
        return read(mvc.perform(authenticated(get(base() + "/" + revision), who.token())).andExpect(status().isOk()));
    }

    /** The revision's edition as a screen shows it now. */
    private int edition(int revision) throws Exception {
        return read(developer, revision).at("/checklist/edition").asInt();
    }

    private static List<Long> itemIds(JsonNode view) {
        List<Long> ids = new ArrayList<>();
        view.at("/lines").forEach(line -> ids.add(line.at("/itemId").asLong()));
        return ids;
    }

    private String typeOf(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).path("type").asText();
    }

    private long idOf(ResultActions result) throws Exception {
        return read(result).path("id").asLong();
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

package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistDocumentEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistDocumentRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistFileEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistFileRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import java.sql.Connection;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The project checklists' tables on a real engine (decision 0032 §1, §5, question 10): the key that
 * keeps a project to one open checklist — several nulls allowed under it, which is the whole trick —
 * the revision number's key, a proof's bytes kept whole in {@code ${bytes}}, an answer's comment in
 * any script, the conditional statements that arbitrate every write, and the purge a project's
 * deletion runs in its own transaction, subqueries included.
 *
 * <p>The HTTP suite runs on SQLite only; what an engine decides — whether a unique key admits two
 * nulls, whether a delete may read another table in its subquery, how a binary column carries a byte
 * — is decided here, on each engine the campaign runs.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the project checklists' tables, on a real engine")
class ChecklistStorageIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    private static final Instant NOW = Instant.parse("2026-09-28T10:15:30.123Z");
    private static final RequestActor ACTOR = new RequestActor("integration", null, null);

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private ChecklistRepository checklists;

    @Autowired
    private ChecklistAnswerRepository answers;

    @Autowired
    private ChecklistEvidenceRepository evidence;

    @Autowired
    private ChecklistFileRepository files;

    @Autowired
    private ChecklistMeasurementRepository measurements;

    @Autowired
    private ChecklistDocumentRepository documents;

    @Autowired
    private SolutionAdministrationService solutions;

    @Autowired
    private DataSource dataSource;

    private static long nextProject = 900_000;

    @Test
    @DisplayName("one open checklist per project: a second open slot is refused, closed ones hold none")
    void theOpenSlot() {
        long project = ++nextProject;
        ChecklistEntity signed = checklists.save(checklist(project, 1, "signed_off", null));
        checklists.save(checklist(project, 2, "superseded", null));
        // Several nulls under the key, on every engine: that is what lets closed revisions pile up.
        checklists.save(checklist(project, 3, "signed_off", null));
        ChecklistEntity open = checklists.save(checklist(project, 4, "draft", 1));

        assertThatThrownBy(() -> checklists.saveAndFlush(checklist(project, 5, "submitted", 1)))
                .as("a second open revision of the same project").isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> checklists.saveAndFlush(checklist(project, 4, "signed_off", null)))
                .as("a revision number taken twice").isInstanceOf(RuntimeException.class);
        // Another project's open slot is its own.
        checklists.saveAndFlush(checklist(project + 1_000, 1, "draft", 1));

        assertThat(checklists.findByProjectIdOrderByRevisionDesc(project)).extracting(ChecklistEntity::getRevision)
                .containsExactly(4, 3, 2, 1);
        assertThat(checklists.findFirstByProjectIdOrderByRevisionDesc(project).orElseThrow().getId()).isEqualTo(open.getId());
        assertThat(signed.getOpenSlot()).isNull();
    }

    @Test
    @DisplayName("each transition matches at the edition its writer read, and frees the slot when it closes the revision")
    void theStatementsArbitrate() {
        long project = ++nextProject;
        long id = checklists.save(checklist(project, 1, "draft", 1)).getId();

        assertThat(checklists.touchDraft(id, 1, "draft")).isEqualTo(1);
        assertThat(checklists.touchDraft(id, 1, "draft")).as("a second write at the edition the first moved on from")
                .isZero();
        assertThat(checklists.submit(id, 2, "draft", "submitted", NOW, "developer", 7L)).isEqualTo(1);
        assertThat(checklists.touchDraft(id, 3, "draft")).as("a submitted revision is not answered").isZero();
        assertThat(checklists.returnToDraft(id, 3, "submitted", "draft", NOW, "lead", "Line 2.")).isEqualTo(1);
        assertThat(checklists.submit(id, 4, "draft", "submitted", NOW, "developer", 7L)).isEqualTo(1);
        assertThat(checklists.signOff(id, 4, "submitted", "signed_off", NOW, "ciso", 8L, true)).as("a stale sign-off")
                .isZero();
        assertThat(checklists.signOff(id, 5, "submitted", "signed_off", NOW, "ciso", 8L, true)).isEqualTo(1);
        assertThat(checklists.supersede(id, 6, List.of("draft", "submitted"), "superseded", NOW, "mover"))
                .as("a signed-off revision is never superseded").isZero();

        ChecklistEntity read = checklists.findById(id).orElseThrow();
        assertThat(read.getStatus()).isEqualTo("signed_off");
        assertThat(read.getEdition()).isEqualTo(6);
        assertThat(read.getOpenSlot()).as("signing off frees the slot").isNull();
        assertThat(read.getSignOffFourEyes()).isTrue();
        assertThat(read.getSignedOffAt()).as("the millisecond, as every ${ts}").isEqualTo(NOW);
        assertThat(read.getReturnReason()).isEqualTo("Line 2.");
        // The slot freed, the next revision opens.
        checklists.saveAndFlush(checklist(project, 2, "draft", 1));
    }

    @Test
    @DisplayName("a proof's file comes back byte for byte, in the engine's binary type; an answer keeps its words")
    void bytesAndWords() throws Exception {
        long project = ++nextProject;
        byte[] content = new byte[3 * 1024 * 1024];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i * 31);
        }
        ChecklistFileEntity file = new ChecklistFileEntity();
        file.setProjectId(project);
        file.setSha256("0".repeat(64));
        file.setSizeBytes((long) content.length);
        file.setContent(content);
        long fileId = files.save(file).getId();
        assertThat(files.findById(fileId).orElseThrow().getContent()).isEqualTo(content);

        String type;
        try (Connection connection = dataSource.getConnection()) {
            type = columnType(connection, "t_checklist_file", "content");
        }
        switch (ENGINE) {
            case MYSQL -> assertThat(type).isEqualTo("longblob");
            case POSTGRES -> assertThat(type).isEqualTo("bytea");
            case SQLITE -> assertThat(type).isEqualTo("blob");
        }

        long checklistId = checklists.save(checklist(project, 1, "draft", 1)).getId();
        String comment = BoundedText.clip("Deux comptes de service subsistent — 两个服务账户 🔐 ".repeat(120), 4_000);
        answers.save(answer(checklistId, 11L, "no", comment));
        assertThat(answers.findByChecklistIdAndItemIdOrderByIdAsc(checklistId, 11L)).singleElement()
                .satisfies(row -> {
                    assertThat(row.getComment()).isEqualTo(comment);
                    assertThat(row.getAnsweredAt()).isEqualTo(NOW);
                    assertThat(row.isNeedsConfirmation()).isFalse();
                });
    }

    @Test
    @DisplayName("a signed document comes back byte for byte, one per revision, in the engine's binary type")
    void theDocuments() throws Exception {
        long project = ++nextProject;
        long checklistId = checklists.save(checklist(project, 1, "signed_off", null)).getId();
        byte[] content = new byte[5 * 1024 * 1024];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i * 131);
        }
        documents.save(document(checklistId, project, content));
        assertThat(documents.findByChecklistId(checklistId)).get().satisfies(read -> {
            assertThat(read.getContent()).isEqualTo(content);
            assertThat(read.getProducedAt()).isEqualTo(NOW);
            assertThat(read.getProductVersion()).isEqualTo("1.2.3");
        });
        assertThatThrownBy(() -> documents.saveAndFlush(document(checklistId, project, new byte[] {1})))
                .as("a second document for the same revision").isInstanceOf(RuntimeException.class);

        String type;
        try (Connection connection = dataSource.getConnection()) {
            type = columnType(connection, "t_checklist_document", "content");
        }
        switch (ENGINE) {
            case MYSQL -> assertThat(type).isEqualTo("longblob");
            case POSTGRES -> assertThat(type).isEqualTo("bytea");
            case SQLITE -> assertThat(type).isEqualTo("blob");
        }
    }

    @Test
    @DisplayName("deleting a project takes its checklists, answers, proofs, files, measurements and documents, in its "
            + "transaction, and nobody else's")
    void deletingAProjectPurges() {
        long solution = solutions.createSolution("Purge " + System.nanoTime(), null, ACTOR).id();
        long doomed = solutions.createProject(solution, "Doomed", null, ACTOR).id();
        long kept = solutions.createProject(solution, "Kept", null, ACTOR).id();
        long doomedChecklist = seed(doomed);
        long keptChecklist = seed(kept);

        solutions.deleteProject(doomed, ACTOR);

        assertThat(checklists.findByProjectIdOrderByRevisionDesc(doomed)).isEmpty();
        assertThat(answers.findByChecklistIdOrderByIdAsc(doomedChecklist)).isEmpty();
        assertThat(evidence.findByChecklistIdOrderByIdAsc(doomedChecklist)).isEmpty();
        assertThat(files.findAll()).noneMatch(file -> file.getProjectId() == doomed);
        assertThat(measurements.findByChecklistIdAndPurposeOrderByIdAsc(doomedChecklist, "sign_off")).isEmpty();
        assertThat(documents.findByChecklistId(doomedChecklist)).isEmpty();

        assertThat(checklists.findByProjectIdOrderByRevisionDesc(kept)).hasSize(1);
        assertThat(answers.findByChecklistIdOrderByIdAsc(keptChecklist)).hasSize(1);
        assertThat(evidence.findByChecklistIdOrderByIdAsc(keptChecklist)).hasSize(1);
        assertThat(files.findAll()).anyMatch(file -> file.getProjectId() == kept);
        assertThat(documents.findByChecklistId(keptChecklist)).isPresent();
        assertThat(measurements.findByChecklistIdAndPurposeOrderByIdAsc(keptChecklist, "sign_off")).singleElement()
                .satisfies(row -> {
                    // The evidence is long text on every engine: a project's figures run past a varchar.
                    assertThat(row.getEvidence()).hasSize(70_000);
                    assertThat(row.getAsOf()).isEqualTo(NOW);
                });
    }

    /** A checklist with an answer, a proof and its file; the checklist's id. */
    private long seed(long project) {
        long checklistId = checklists.save(checklist(project, 1, "draft", 1)).getId();
        answers.save(answer(checklistId, 21L, "yes", null));
        ChecklistFileEntity file = new ChecklistFileEntity();
        file.setProjectId(project);
        file.setSha256("1".repeat(64));
        file.setSizeBytes(3L);
        file.setContent(new byte[] {1, 2, 3});
        long fileId = files.save(file).getId();
        ChecklistEvidenceEntity proof = new ChecklistEvidenceEntity();
        proof.setChecklistId(checklistId);
        proof.setItemId(21L);
        proof.setKind("file");
        proof.setFileId(fileId);
        proof.setFileName("proof.pdf");
        proof.setMediaType("application/pdf");
        proof.setFileSize(3L);
        proof.setFileSha256("1".repeat(64));
        proof.setPerformedOn(NOW);
        proof.setAddedBy("developer");
        proof.setAddedById(7L);
        proof.setAddedAt(NOW);
        proof.setEdition(2);
        evidence.save(proof);
        ChecklistMeasurementEntity measured = new ChecklistMeasurementEntity();
        measured.setChecklistId(checklistId);
        measured.setItemId(21L);
        measured.setPurpose("sign_off");
        measured.setRuleKind("findings_threshold");
        measured.setRuleDigest("2".repeat(64));
        measured.setBoundRule("{\"kind\":\"findings_threshold\"}");
        measured.setOutcome("pass");
        measured.setAsOf(NOW);
        measured.setComputedAt(NOW);
        measured.setComputedBy("ciso");
        measured.setAnswerValue("yes");
        measured.setReconciliation("consistent");
        measured.setEvidenceDigest("3".repeat(64));
        measured.setEvidence("e".repeat(70_000));
        measurements.save(measured);
        documents.save(document(checklistId, project, new byte[] {4, 5, 6}));
        return checklistId;
    }

    private static ChecklistDocumentEntity document(long checklistId, long project, byte[] content) {
        ChecklistDocumentEntity document = new ChecklistDocumentEntity();
        document.setChecklistId(checklistId);
        document.setProjectId(project);
        document.setContent(content);
        document.setSizeBytes((long) content.length);
        document.setSha256("4".repeat(64));
        document.setWorkbookSha256("5".repeat(64));
        document.setWorkbookSignature("M".repeat(96));
        document.setStatementSha256("6".repeat(64));
        document.setStatementSignature("N".repeat(96));
        document.setSigningKeyId("7".repeat(64));
        document.setProductVersion("1.2.3");
        document.setProducedAt(NOW);
        return document;
    }

    private static ChecklistEntity checklist(long project, int revision, String status, Integer openSlot) {
        ChecklistEntity row = new ChecklistEntity();
        row.setProjectId(project);
        row.setTemplateVersionId(1L);
        row.setRevision(revision);
        row.setStatus(status);
        row.setEdition(1);
        row.setOpenSlot(openSlot);
        row.setAuthorId(7L);
        row.setAuthor("developer");
        row.setOpenedAt(NOW);
        row.setOpenedBy("developer");
        return row;
    }

    private static ChecklistAnswerEntity answer(long checklistId, long itemId, String value, String comment) {
        ChecklistAnswerEntity row = new ChecklistAnswerEntity();
        row.setChecklistId(checklistId);
        row.setItemId(itemId);
        row.setValue(value);
        row.setComment(comment);
        row.setAnsweredBy("developer");
        row.setAnsweredById(7L);
        row.setAnsweredAt(NOW);
        row.setEdition(2);
        return row;
    }

    /** The column's declared type, lowercased, in the engine's own vocabulary. */
    private static String columnType(Connection connection, String table, String column) throws Exception {
        for (String name : new String[] {table, table.toUpperCase(Locale.ROOT)}) {
            try (ResultSet columns = connection.getMetaData().getColumns(connection.getCatalog(), null, name, null)) {
                while (columns.next()) {
                    if (columns.getString("COLUMN_NAME").equalsIgnoreCase(column)) {
                        return columns.getString("TYPE_NAME").toLowerCase(Locale.ROOT);
                    }
                }
            }
        }
        throw new AssertionError(table + "." + column + " was not found");
    }
}

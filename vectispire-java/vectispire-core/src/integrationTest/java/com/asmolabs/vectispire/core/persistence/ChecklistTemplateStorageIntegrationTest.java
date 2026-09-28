package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionEntity;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionSummary;
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
 * The checklist templates' tables on a real engine (decision 0032 §1): the workbook's bytes kept
 * whole in {@code ${bytes}}, the template's words kept as written, the listing's projection, the
 * conditional statements that arbitrate every change, and the keys that arbitrate two drafts.
 *
 * <p>{@code SchemaParityIntegrationTest} validates the mappings against the schema on the typed
 * engines; this writes and reads back through them, which is what proves them on SQLite and what
 * shows on the others whether a mapping that validates also carries the value — a {@code byte[]}
 * mapped as a large object validates nowhere, and one read through a character set would change
 * some bytes on the way.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the checklist templates' tables, on a real engine")
class ChecklistTemplateStorageIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    private static final Instant NOW = Instant.parse("2026-09-28T10:15:30.123Z");

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
    private ChecklistTemplateRepository templates;

    @Autowired
    private ChecklistTemplateVersionRepository versions;

    @Autowired
    private ChecklistItemRepository items;

    @Autowired
    private DataSource dataSource;

    @Test
    @DisplayName("a workbook of several megabytes comes back byte for byte, every byte value included")
    void theWorkbookIsKeptWhole() {
        // 3 MB, far past MySQL's `blob` (64 KiB), and every value from 0 to 255, so that a column read
        // back through a character set would show it.
        byte[] workbook = new byte[3 * 1024 * 1024];
        for (int i = 0; i < workbook.length; i++) {
            workbook[i] = (byte) (i * 31);
        }
        ChecklistTemplateVersionEntity saved = versions.save(version(template("bytes"), 1, workbook));

        ChecklistTemplateVersionEntity read = versions.findById(saved.getId()).orElseThrow();
        assertThat(read.getSourceBytes()).isEqualTo(workbook);
        assertThat(read.getSourceSize()).isEqualTo(workbook.length);
        assertThat(read.getImportedAt()).as("the millisecond, as every ${ts}").isEqualTo(NOW);
    }

    @Test
    @DisplayName("the column is the engine's binary type, never a large object")
    void theColumnIsBinary() throws Exception {
        String type;
        try (Connection connection = dataSource.getConnection()) {
            type = columnType(connection, "t_checklist_template_version", "source_bytes");
        }
        switch (ENGINE) {
            case MYSQL -> assertThat(type).isEqualTo("longblob");
            // `oid` is what `@Lob` would have made the entity expect.
            case POSTGRES -> assertThat(type).isEqualTo("bytea");
            case SQLITE -> assertThat(type).isEqualTo("blob");
        }
    }

    @Test
    @DisplayName("an item keeps the template's words as written: long, and in any script")
    void anItemKeepsItsWords() {
        ChecklistTemplateVersionEntity version = versions.save(version(template("words"), 1, new byte[] {1}));
        // Cut on a character boundary: half an emoji is not a string any engine should be asked to keep.
        String control = BoundedText.clip("Chaque compte appartient à une personne nommée — 每个账户 🔐 ".repeat(80), 4_000);
        String domain = "Identité ".repeat(112).substring(0, 1_000);
        ChecklistItemEntity item = item(version.getId(), "text:" + "a".repeat(64), 1);
        item.setControl(control);
        item.setKpi("K".repeat(4_000));
        item.setDomain(domain);
        item.setObjective(domain);
        item.setContact("é".repeat(255));
        items.save(item);

        ChecklistItemEntity read = items.findByVersionIdOrderByPositionAsc(version.getId()).getFirst();
        assertThat(read.getControl()).isEqualTo(control);
        assertThat(read.getKpi()).hasSize(4_000);
        assertThat(read.getDomain()).isEqualTo(domain);
        assertThat(read.getContact()).hasSize(255);
        assertThat(read.getItemKey()).isEqualTo("text:" + "a".repeat(64));
    }

    @Test
    @DisplayName("the listing's projection counts the items and leaves the bytes out, on every engine")
    void theListingProjection() {
        ChecklistTemplateEntity template = template("listing");
        ChecklistTemplateVersionEntity first = versions.save(version(template, 1, new byte[] {1, 2, 3}));
        first.setStatus("published");
        first.setPublishedAt(NOW);
        versions.save(first);
        versions.save(version(template, 2, new byte[] {4}));
        items.saveAll(List.of(item(first.getId(), "id:A-1", 1), item(first.getId(), "id:A-2", 2)));

        List<ChecklistTemplateVersionSummary> summaries = versions.summariesOf(template.getId());
        assertThat(summaries).extracting(ChecklistTemplateVersionSummary::ordinal).containsExactly(1, 2);
        assertThat(summaries).extracting(ChecklistTemplateVersionSummary::itemCount).containsExactly(2L, 0L);
        assertThat(versions.lastOrdinal(template.getId())).isEqualTo(2);
        assertThat(versions.publishedNewestFirst(template.getId())).containsExactly(first.getId());
        assertThat(versions.existsByTemplateIdAndStatus(template.getId(), "draft")).isTrue();
    }

    @Test
    @DisplayName("each change matches at the revision its writer read, and nothing once another has moved it")
    void theStatementsArbitrate() {
        ChecklistTemplateVersionEntity draft = versions.save(version(template("arbitrate"), 1, new byte[] {1}));
        long id = draft.getId();

        assertThat(versions.editDraft(id, 1, "draft", "{\"form\":1}", true, "[]", "[]")).isEqualTo(1);
        assertThat(versions.editDraft(id, 1, "draft", "{}", false, null, "[]"))
                .as("a second edit at the revision the first moved on from").isZero();
        assertThat(versions.publish(id, 1, "draft", "published", NOW, "late")).isZero();
        assertThat(versions.publish(id, 2, "draft", "published", NOW, "reviewer")).isEqualTo(1);
        assertThat(versions.publish(id, 2, "draft", "published", NOW, "twice")).isZero();
        assertThat(versions.retire(id, 3, "published", "retired", NOW, "retirer")).isEqualTo(1);

        ChecklistTemplateVersionEntity read = versions.findById(id).orElseThrow();
        assertThat(read.getStatus()).isEqualTo("retired");
        assertThat(read.getRevision()).isEqualTo(4);
        assertThat(read.getLayout()).isEqualTo("{\"form\":1}");
        assertThat(read.isOffersNotApplicable()).isTrue();
        assertThat(read.getPublishedBy()).isEqualTo("reviewer");
        assertThat(read.getPublishedAt()).isEqualTo(NOW);
        assertThat(read.getRetiredBy()).isEqualTo("retirer");
    }

    @Test
    @DisplayName("the keys refuse a second template under a slug, a second version under a number, a second item under a key")
    void theKeysArbitrate() {
        ChecklistTemplateEntity template = template("keys");
        ChecklistTemplateVersionEntity version = versions.save(version(template, 1, new byte[] {1}));
        items.save(item(version.getId(), "id:K-1", 1));

        assertThatThrownBy(() -> template("keys")).as("the slug").isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> versions.save(version(template, 1, new byte[] {2})))
                .as("the number within a template").isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> items.save(item(version.getId(), "id:K-1", 2)))
                .as("the key within a version").isInstanceOf(RuntimeException.class);

        assertThat(versions.summariesOf(template.getId())).hasSize(1);
        assertThat(items.findByVersionIdOrderByPositionAsc(version.getId())).hasSize(1);
        assertThat(items.deleteByVersion(version.getId())).isEqualTo(1);
    }

    private ChecklistTemplateEntity template(String slug) {
        ChecklistTemplateEntity template = new ChecklistTemplateEntity();
        template.setSlug(slug);
        template.setName("Template " + slug);
        template.setCreatedAt(NOW);
        template.setCreatedBy("importer");
        return templates.save(template);
    }

    private static ChecklistTemplateVersionEntity version(ChecklistTemplateEntity template, int ordinal, byte[] workbook) {
        ChecklistTemplateVersionEntity version = new ChecklistTemplateVersionEntity();
        version.setTemplateId(template.getId());
        version.setOrdinal(ordinal);
        version.setStatus("draft");
        version.setRevision(1);
        version.setSourceSha256("0".repeat(64));
        version.setSourceSize((long) workbook.length);
        version.setSourceBytes(workbook);
        version.setDraftAuthors("[{\"accountId\":1,\"username\":\"importer\"}]");
        version.setImportedAt(NOW);
        version.setImportedBy("importer");
        return version;
    }

    private static ChecklistItemEntity item(long versionId, String key, int position) {
        ChecklistItemEntity item = new ChecklistItemEntity();
        item.setVersionId(versionId);
        item.setItemKey(key);
        item.setPosition(position);
        item.setDomain("Identity");
        item.setObjective("Accounts are personal");
        item.setControl("Every account belongs to one named person.");
        item.setContact("Security officer");
        item.setKpi("");
        item.setContentDigest("f".repeat(64));
        item.setSheetRow(6 + position);
        item.setEvidenceKind("none");
        return item;
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

package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Optional;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("a checklist item's identity")
class ChecklistItemTest {

    static ChecklistItem item(String domain, String objective, String control, String contact, String kpi) {
        return new ChecklistItem(ItemKey.fromControl(control), 1, domain, objective, control, contact, kpi, 7,
                EvidenceRequirement.NONE, Optional.empty());
    }

    private static final ChecklistItem ITEM = item("Identity", "1. Accounts are personal",
            "Every account belongs to one named person.", "Security officer", "No shared account");

    private static ChecklistItem copy(ChecklistItem item, UnaryOperator<String[]> change) {
        String[] fields = {item.domain(), item.objective(), item.control(), item.contact(), item.kpi()};
        String[] changed = change.apply(fields);
        return new ChecklistItem(item.key(), item.position(), changed[0], changed[1], changed[2], changed[3], changed[4],
                item.row(), item.evidence(), item.boundRule());
    }

    @Nested
    @DisplayName("the content digest")
    class Digest {

        @Test
        @DisplayName("is frozen: a stored digest must match the one computed for the same words next year")
        void frozen() {
            // A data contract, like an issue's fingerprint: if this value moves, every stored item reads as
            // changed at the next version, and every carried answer waits for a confirmation nobody asked for.
            // Computed apart as SHA-256 over the NUL-joined fields, the form prefix first, "none" and "unbound".
            assertThat(ITEM.contentDigest()).isEqualTo("2d4a18b49fa4797ab190cecfa05d039ae1de9c308f57ea142613097432916c1e");
        }

        @Test
        @DisplayName("moves with the domain, the objective, the control and the KPI")
        void wording() {
            assertThat(copy(ITEM, f -> new String[] {"Access", f[1], f[2], f[3], f[4]}).contentDigest()).isNotEqualTo(ITEM.contentDigest());
            assertThat(copy(ITEM, f -> new String[] {f[0], "Other", f[2], f[3], f[4]}).contentDigest()).isNotEqualTo(ITEM.contentDigest());
            assertThat(copy(ITEM, f -> new String[] {f[0], f[1], "Every account is named.", f[3], f[4]}).contentDigest())
                    .isNotEqualTo(ITEM.contentDigest());
            assertThat(copy(ITEM, f -> new String[] {f[0], f[1], f[2], f[3], "At most one"}).contentDigest())
                    .isNotEqualTo(ITEM.contentDigest());
        }

        @Test
        @DisplayName("moves with the evidence requirement and its validity, and with the bound rule")
        void requirement() {
            ChecklistItem file = ITEM.withEvidence(new EvidenceRequirement(EvidenceRequirement.Kind.FILE, Optional.empty()));
            ChecklistItem yearly = ITEM.withEvidence(new EvidenceRequirement(EvidenceRequirement.Kind.FILE, Optional.of(12)));

            assertThat(file.contentDigest()).isNotEqualTo(ITEM.contentDigest());
            assertThat(yearly.contentDigest()).isNotEqualTo(file.contentDigest());
            assertThat(ITEM.withBoundRule(Optional.of("{\"kind\":\"findings_threshold\"}")).contentDigest())
                    .isNotEqualTo(ITEM.contentDigest());
        }

        @Test
        @DisplayName("does not tell two fields apart by moving words from one to the other")
        void fieldBoundaries() {
            ChecklistItem left = item("Identity Access", "", "Control", "", "");
            ChecklistItem right = item("Identity", "Access", "Control", "", "");

            assertThat(left.contentDigest()).isNotEqualTo(right.contentDigest());
        }

        @Test
        @DisplayName("ignores what a workbook changes without anybody changing the words")
        void normalisation() {
            ChecklistItem respaced = copy(ITEM, f -> new String[] {" Identity ", f[1].replace(" ", " "),
                    f[2].replace(" named ", " named\n"), f[3], f[4] + "​"});

            assertThat(respaced.contentDigest()).isEqualTo(ITEM.contentDigest());
        }

        @Test
        @DisplayName("keeps case: a capital is a change of wording")
        void caseKept() {
            assertThat(copy(ITEM, f -> new String[] {f[0], f[1], f[2].toUpperCase(), f[3], f[4]}).contentDigest())
                    .isNotEqualTo(ITEM.contentDigest());
        }

        @Test
        @DisplayName("leaves out the contact, the row, the position and the key: moving a line changes nothing it asks")
        void outside() {
            ChecklistItem moved = new ChecklistItem(ItemKey.fromId("AC-1"), 9, ITEM.domain(), ITEM.objective(), ITEM.control(),
                    "Someone else", ITEM.kpi(), 40, ITEM.evidence(), ITEM.boundRule());

            assertThat(moved.contentDigest()).isEqualTo(ITEM.contentDigest());
        }
    }

    @Nested
    @DisplayName("the key")
    class Key {

        @Test
        @DisplayName("from a control is folded to lower case, so a capital pairs as changed rather than as removed")
        void folded() {
            assertThat(ItemKey.fromControl("Backups are TESTED.")).isEqualTo(ItemKey.fromControl("  backups are tested. "));
            assertThat(ItemKey.fromControl("Backups are tested.")).isNotEqualTo(ItemKey.fromControl("Backups are restored."));
        }

        @Test
        @DisplayName("is frozen, like the digest")
        void frozen() {
            assertThat(ItemKey.fromControl("Every account belongs to one named person.").value()).isEqualTo(
                    "text:6fdeb390bf9766a51308a9ab57b1f281403cfbefc11149ff7189176961613719");
        }

        @Test
        @DisplayName("from an id never equals one from a control")
        void prefixes() {
            assertThat(ItemKey.fromId("AC-1").value()).isEqualTo("id:AC-1");
            assertThat(ItemKey.fromControl("AC-1").value()).startsWith("text:");
        }

        @Test
        @DisplayName("refuses a blank id or control, and a key nobody derived")
        void refusals() {
            assertThatThrownBy(() -> ItemKey.fromId("  ")).hasMessageContaining("id is blank");
            assertThatThrownBy(() -> ItemKey.fromControl("​")).hasMessageContaining("control is blank");
            assertThatThrownBy(() -> ItemKey.fromId("x".repeat(ItemKey.MAX_ID + 1))).hasMessageContaining("longer than");
            assertThatThrownBy(() -> new ItemKey("AC-1")).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    @DisplayName("an item asks something: a blank control is refused")
    void blankControl() {
        assertThatThrownBy(() -> new ChecklistItem(ItemKey.fromId("A"), 1, "", "", " ", "", "", 3, EvidenceRequirement.NONE,
                Optional.empty()))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("Row 3 has no control");
    }

    @Test
    @DisplayName("an evidence validity needs a proof to apply to, and a sensible length")
    void evidence() {
        assertThatThrownBy(() -> new EvidenceRequirement(EvidenceRequirement.Kind.NONE, Optional.of(12)))
                .hasMessageContaining("asks for none");
        assertThatThrownBy(() -> new EvidenceRequirement(EvidenceRequirement.Kind.FILE, Optional.of(0)))
                .hasMessageContaining("between 1 and");
        assertThatThrownBy(() -> new EvidenceRequirement(EvidenceRequirement.Kind.FILE,
                Optional.of(EvidenceRequirement.MAX_VALIDITY_MONTHS + 1)))
                .hasMessageContaining("between 1 and");
    }

    @Test
    @DisplayName("a requirement is named by its wire name, and anything else is refused in words, not by valueOf")
    void evidenceKindParsed() {
        assertThat(EvidenceRequirement.Kind.parse(" Link_Or_File ")).isEqualTo(EvidenceRequirement.Kind.LINK_OR_FILE);
        assertThat(EvidenceRequirement.Kind.parse("none")).isEqualTo(EvidenceRequirement.Kind.NONE);
        assertThatThrownBy(() -> EvidenceRequirement.Kind.parse("photo"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("none, link_or_file, file").hasMessageContaining("\"photo\"");
        assertThatThrownBy(() -> EvidenceRequirement.Kind.parse(null)).hasMessageContaining("none was given");
    }
}

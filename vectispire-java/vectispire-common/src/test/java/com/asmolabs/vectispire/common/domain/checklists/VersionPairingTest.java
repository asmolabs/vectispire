package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("pairing a new version's items with the previous version's")
class VersionPairingTest {

    private static ChecklistItem item(String control, String kpi, int row) {
        return new ChecklistItem(ItemKey.fromControl(control), row, "Domain", "Objective", control, "", kpi, row,
                EvidenceRequirement.NONE, Optional.empty());
    }

    private static final ChecklistItem KEPT = item("Backups are tested.", "", 1);
    private static final ChecklistItem MOVED_KPI = item("Access is reviewed.", "Every quarter", 2);
    private static final ChecklistItem DROPPED = item("Fax lines are disabled.", "", 3);
    private static final ChecklistItem REWORDED = item("Passwords are long.", "", 4);

    private static final List<ChecklistItem> PREVIOUS = List.of(KEPT, MOVED_KPI, DROPPED, REWORDED);

    private static final ChecklistItem KEPT_NEXT = item("Backups are tested.", "", 1);
    private static final ChecklistItem MOVED_KPI_NEXT = item("Access is reviewed.", "Every month", 2);
    private static final ChecklistItem ADDED = item("Secrets are rotated.", "", 3);
    private static final ChecklistItem REWORDED_NEXT = item("Passphrases have at least fifteen characters.", "", 4);

    private static final List<ChecklistItem> NEXT = List.of(KEPT_NEXT, MOVED_KPI_NEXT, ADDED, REWORDED_NEXT);

    @Test
    @DisplayName("same key and digest is unchanged, same key and another digest changed, the rest added or removed")
    void automatic() {
        VersionPairing pairing = VersionPairing.of(PREVIOUS, NEXT, List.of());

        assertThat(pairing.changes()).containsExactly(
                new VersionPairing.Unchanged(KEPT, KEPT_NEXT),
                new VersionPairing.Changed(MOVED_KPI, MOVED_KPI_NEXT, false),
                new VersionPairing.Added(ADDED),
                new VersionPairing.Added(REWORDED_NEXT),
                new VersionPairing.Removed(DROPPED),
                new VersionPairing.Removed(REWORDED));
        assertThat(pairing.next()).isEqualTo(NEXT);
    }

    @Test
    @DisplayName("a pair made by hand gives the new item the old key and marks it changed")
    void byHand() {
        VersionPairing pairing = VersionPairing.of(PREVIOUS, NEXT,
                List.of(new VersionPairing.ManualPair(REWORDED_NEXT.key(), REWORDED.key())));

        ChecklistItem rekeyed = REWORDED_NEXT.withKey(REWORDED.key());
        assertThat(pairing.changes()).containsExactly(
                new VersionPairing.Unchanged(KEPT, KEPT_NEXT),
                new VersionPairing.Changed(MOVED_KPI, MOVED_KPI_NEXT, false),
                new VersionPairing.Added(ADDED),
                new VersionPairing.Changed(REWORDED, rekeyed, true),
                new VersionPairing.Removed(DROPPED));
        assertThat(pairing.next()).containsExactly(KEPT_NEXT, MOVED_KPI_NEXT, ADDED, rekeyed);
    }

    @Test
    @DisplayName("a pair by hand is changed even when the two say the same thing under different ids")
    void byHandAlwaysChanged() {
        ChecklistItem before = new ChecklistItem(ItemKey.fromId("A-1"), 1, "", "", "Same words.", "", "", 1,
                EvidenceRequirement.NONE, Optional.empty());
        ChecklistItem after = new ChecklistItem(ItemKey.fromId("B-1"), 1, "", "", "Same words.", "", "", 1,
                EvidenceRequirement.NONE, Optional.empty());

        VersionPairing pairing = VersionPairing.of(List.of(before), List.of(after),
                List.of(new VersionPairing.ManualPair(after.key(), before.key())));

        assertThat(pairing.changes()).containsExactly(new VersionPairing.Changed(before, after.withKey(before.key()), true));
    }

    @Test
    @DisplayName("refuses a pair that joins anything but an added item and a removed one, or pairs an item twice")
    void refusals() {
        assertThatThrownBy(() -> VersionPairing.of(PREVIOUS, NEXT,
                List.of(new VersionPairing.ManualPair(KEPT_NEXT.key(), DROPPED.key()))))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("one the new version adds; the item on row 1 is not");
        assertThatThrownBy(() -> VersionPairing.of(PREVIOUS, NEXT,
                List.of(new VersionPairing.ManualPair(ADDED.key(), KEPT.key()))))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("one the new version removes");
        assertThatThrownBy(() -> VersionPairing.of(PREVIOUS, NEXT, List.of(
                new VersionPairing.ManualPair(ADDED.key(), DROPPED.key()),
                new VersionPairing.ManualPair(REWORDED_NEXT.key(), DROPPED.key()))))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("paired twice");
        assertThatThrownBy(() -> VersionPairing.of(PREVIOUS, NEXT, List.of(
                new VersionPairing.ManualPair(ADDED.key(), DROPPED.key()),
                new VersionPairing.ManualPair(ADDED.key(), REWORDED.key()))))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("paired twice");
        assertThatThrownBy(() -> VersionPairing.of(PREVIOUS, NEXT,
                List.of(new VersionPairing.ManualPair(ItemKey.fromControl("nowhere"), DROPPED.key()))))
                .hasMessageContaining("an item that does not exist");
    }

    @Test
    @DisplayName("a capital changed in a control pairs as changed, its answer carried to be confirmed")
    void capital() {
        ChecklistItem recased = item("Backups are TESTED.", "", 1);
        List<ChecklistItem> next = new ArrayList<>(List.of(recased));

        assertThat(VersionPairing.of(List.of(KEPT), next, List.of()).changes())
                .containsExactly(new VersionPairing.Changed(KEPT, recased, false));
    }
}

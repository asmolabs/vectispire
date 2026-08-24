package com.asmolabs.vectispire.common.domain.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditChain.Entry;
import com.asmolabs.vectispire.common.domain.audit.AuditChain.VerifiableEntry;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("audit integrity chain")
class AuditChainTest {

    private static final Instant AT = Instant.parse("2026-08-10T08:13:58.322Z");

    private static Entry base() {
        return new Entry(null, AT, "LOGIN_SUCCESS", "alice", "alice", "10.0.0.4", "Mozilla/5.0", "Successful login");
    }

    @Nested
    @DisplayName("the entry hash")
    class EntryHash {

        @Test
        @DisplayName("depends on the instant, not on how it was expressed")
        void independentOfConstruction() {
            // The canonical form is UTC, so the hash does not depend on the timezone of the
            // machine computing it. That is the property that matters for a control meant to
            // be verifiable somewhere other than where it was written.
            Instant sameInstant = Instant.EPOCH
                    .plus(AT.toEpochMilli(), ChronoUnit.MILLIS)
                    .atZone(java.time.ZoneId.of("Asia/Tokyo"))
                    .toInstant();

            assertThat(AuditChain.computeEntryHash(withTimestamp(sameInstant)))
                    .isEqualTo(AuditChain.computeEntryHash(base()));
        }

        @Test
        @DisplayName("tells two instants apart to the millisecond")
        void millisecondResolution() {
            assertThat(AuditChain.computeEntryHash(withTimestamp(AT.plusMillis(1))))
                    .isNotEqualTo(AuditChain.computeEntryHash(base()));
        }

        @Test
        @DisplayName("survives an instant landing exactly on the second")
        void wholeSecondsAreStillThreeDigits() {
            // The trap the canonical formatter exists for: `Instant::toString` drops the
            // fraction when it is zero, so a whole second would hash as `...:00Z` here and
            // `...:00.000Z` in a backend that always prints three digits. The alarm would name
            // integrity when the cause was formatting.
            Instant whole = Instant.parse("2026-08-10T08:13:58Z");

            assertThat(AuditChain.computeEntryHash(withTimestamp(whole)))
                    .isNotEqualTo(AuditChain.computeEntryHash(withTimestamp(whole.plusMillis(1))));
        }

        @ParameterizedTest(name = "changes when {0} changes")
        @ValueSource(strings = {"operationType", "resourceId", "userId", "ipAddress", "userAgent", "description", "previousHash"})
        void sensitiveToEveryField(String field) {
            Entry b = base();
            Entry altered = switch (field) {
                case "operationType" -> new Entry(b.previousHash(), b.timestamp(), "altered", b.resourceId(), b.userId(), b.ipAddress(), b.userAgent(), b.description());
                case "resourceId" -> new Entry(b.previousHash(), b.timestamp(), b.operationType(), "altered", b.userId(), b.ipAddress(), b.userAgent(), b.description());
                case "userId" -> new Entry(b.previousHash(), b.timestamp(), b.operationType(), b.resourceId(), "altered", b.ipAddress(), b.userAgent(), b.description());
                case "ipAddress" -> new Entry(b.previousHash(), b.timestamp(), b.operationType(), b.resourceId(), b.userId(), "altered", b.userAgent(), b.description());
                case "userAgent" -> new Entry(b.previousHash(), b.timestamp(), b.operationType(), b.resourceId(), b.userId(), b.ipAddress(), "altered", b.description());
                case "description" -> new Entry(b.previousHash(), b.timestamp(), b.operationType(), b.resourceId(), b.userId(), b.ipAddress(), b.userAgent(), "altered");
                case "previousHash" -> new Entry("altered", b.timestamp(), b.operationType(), b.resourceId(), b.userId(), b.ipAddress(), b.userAgent(), b.description());
                default -> throw new IllegalArgumentException(field);
            };

            assertThat(AuditChain.computeEntryHash(altered)).isNotEqualTo(AuditChain.computeEntryHash(b));
        }

        @Test
        @DisplayName("treats null and the empty string as the same absence")
        void nullEqualsEmpty() {
            Entry b = base();
            Entry nulled = new Entry(b.previousHash(), b.timestamp(), b.operationType(), b.resourceId(), b.userId(), b.ipAddress(), null, b.description());
            Entry empty = new Entry(b.previousHash(), b.timestamp(), b.operationType(), b.resourceId(), b.userId(), b.ipAddress(), "", b.description());

            assertThat(AuditChain.computeEntryHash(nulled)).isEqualTo(AuditChain.computeEntryHash(empty));
        }

        @Test
        @DisplayName("does not let content imitate a field boundary")
        void separatorCannotBeForged() {
            Entry b = base();
            Entry split = new Entry(b.previousHash(), b.timestamp(), b.operationType(), "ab", "cd", b.ipAddress(), b.userAgent(), b.description());
            Entry shifted = new Entry(b.previousHash(), b.timestamp(), b.operationType(), "a", "bcd", b.ipAddress(), b.userAgent(), b.description());

            assertThat(AuditChain.computeEntryHash(split)).isNotEqualTo(AuditChain.computeEntryHash(shifted));
        }

        private static Entry withTimestamp(Instant at) {
            Entry b = base();
            return new Entry(b.previousHash(), at, b.operationType(), b.resourceId(), b.userId(), b.ipAddress(), b.userAgent(), b.description());
        }
    }

    @Nested
    @DisplayName("verification")
    class Verification {

        @Test
        @DisplayName("accepts an intact chain")
        void acceptsIntact() {
            assertThat(AuditChain.verifyChain(chained(5)))
                    .isEqualTo(new AuditChain.Verification(null, 0));
        }

        @Test
        @DisplayName("accepts an empty log")
        void acceptsEmpty() {
            assertThat(AuditChain.verifyChain(List.of()))
                    .isEqualTo(new AuditChain.Verification(null, 0));
        }

        @Test
        @DisplayName("reports an entry whose content was rewritten after the fact")
        void detectsModification() {
            List<VerifiableEntry> entries = new ArrayList<>(chained(5));
            VerifiableEntry victim = entries.get(2);
            Entry e = victim.entry();
            entries.set(2, new VerifiableEntry(victim.id(), victim.entryHash(), new Entry(
                    e.previousHash(), e.timestamp(), e.operationType(), e.resourceId(), e.userId(),
                    e.ipAddress(), e.userAgent(), "Rewritten description")));

            assertThat(AuditChain.verifyChain(entries).broken())
                    .contains("entry-2")
                    .contains("no longer matches");
        }

        @Test
        @DisplayName("reports a deleted entry through the successor that pointed at it")
        void detectsDeletion() {
            List<VerifiableEntry> entries = new ArrayList<>(chained(5));
            entries.remove(2);

            assertThat(AuditChain.verifyChain(entries).broken())
                    .contains("entry-3")
                    .contains("deleted");
        }

        @Test
        @DisplayName("counts entries predating the chaining without refusing them")
        void countsLegacyEntries() {
            // They carry no hash because they predate the feature, not because anyone touched
            // them. "These rows are not verifiable" is information, not an absence of it.
            List<VerifiableEntry> entries = new ArrayList<>();
            Entry old = new Entry(null, AT.minusSeconds(60), "SETTING_UPDATED", "0", "admin", null, null, "Before chaining");
            entries.add(new VerifiableEntry("legacy", null, old));
            entries.addAll(chained(3));

            assertThat(AuditChain.verifyChain(entries)).isEqualTo(new AuditChain.Verification(null, 1));
        }

        @Test
        @DisplayName("refuses an unhashed entry dated after the chaining started")
        void detectsHandPlacedRow() {
            // **Dated, not merely placed in the middle of the list.** Position stopped meaning
            // anything once two instances writing at the same instant produce legitimate
            // branches. What tells a hand-placed row from an inherited one is its date.
            List<VerifiableEntry> entries = new ArrayList<>(chained(3));
            entries.add(new VerifiableEntry("inserted", null,
                    new Entry(null, AT.plusSeconds(30), "SETTING_UPDATED", "9", "admin", null, null, "Placed by hand")));

            assertThat(AuditChain.verifyChain(entries).broken())
                    .contains("inserted")
                    .contains("inserted or modified");
        }

        @Test
        @DisplayName("accepts two branches born of the same link")
        void acceptsConcurrentBranches() {
            // Two instances reading the same tail write two entries carrying the same
            // predecessor. The chain forks, and an honest log used to declare itself broken. A
            // false alarm in an integrity check is worse than useless: you learn to ignore it,
            // and it then covers the real ones.
            List<VerifiableEntry> trunk = new ArrayList<>(chained(2));
            String tip = trunk.get(1).entryHash();

            for (int i = 0; i < 2; i++) {
                Entry branch = new Entry(tip, AT.plusSeconds(10 + i), "SETTING_UPDATED", "b" + i, "admin", null, null, "Branch " + i);
                trunk.add(new VerifiableEntry("branch-" + i, AuditChain.computeEntryHash(branch), branch));
            }

            assertThat(AuditChain.verifyChain(trunk).broken()).isNull();
        }

        @Test
        @DisplayName("does not depend on the order the entries come back in")
        void orderIndependent() {
            List<VerifiableEntry> shuffled = new ArrayList<>(chained(5));
            java.util.Collections.reverse(shuffled);

            assertThat(AuditChain.verifyChain(shuffled).broken()).isNull();
        }
    }

    @Nested
    @DisplayName("rebuilding")
    class Rebuild {

        @Test
        @DisplayName("produces a chain that verifies, without touching content")
        void rebuildsVerifiably() {
            List<VerifiableEntry> broken = new ArrayList<>(chained(4));
            broken.set(1, new VerifiableEntry(broken.get(1).id(), "0".repeat(64), broken.get(1).entry()));

            List<VerifiableEntry> rebuilt = AuditChain.rebuildChain(broken);

            assertThat(AuditChain.verifyChain(rebuilt).broken()).isNull();
            assertThat(rebuilt).extracting(e -> e.entry().description())
                    .isEqualTo(broken.stream().map(e -> e.entry().description()).toList());
        }
    }

    private static List<VerifiableEntry> chained(int count) {
        List<VerifiableEntry> entries = new ArrayList<>(count);
        String previousHash = null;
        for (int i = 0; i < count; i++) {
            Entry entry = new Entry(previousHash, AT.plusSeconds(i), "SETTING_UPDATED", String.valueOf(i), "admin", null, null, "Change " + i);
            String hash = AuditChain.computeEntryHash(entry);
            entries.add(new VerifiableEntry("entry-" + i, hash, entry));
            previousHash = hash;
        }
        return entries;
    }
}

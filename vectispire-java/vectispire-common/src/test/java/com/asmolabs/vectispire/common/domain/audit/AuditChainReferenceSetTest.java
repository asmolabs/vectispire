package com.asmolabs.vectispire.common.domain.audit;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The audit chain's answers, for the control plane's Rust port (`vectispire-rust/crates/cp-audit`) to
 * reproduce — see {@code ReferenceSet}.
 *
 * <p><b>The decisive property is the bytes of the hash.</b> An installation's audit log is a chain the
 * Java code started: the Rust control plane continues it, and a hash that differs by one character for
 * the same entry reads as tampering of the whole log from the switchover on. So every field shape the
 * column can hold is here — absent and empty (which hash alike, on purpose), the fraction of an instant at
 * every precision the engines return, characters outside the BMP, a NUL inside a value — with the
 * canonical instant and the hash this side computes.
 *
 * <p>The verifications and the rebuilds are the same graph rules, on small logs built to break each one.
 */
class AuditChainReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private static AuditChain.Entry entry(
            String previous, String at, String operation, String resource, String user, String ip, String agent,
            String description) {
        return new AuditChain.Entry(
                previous, at == null ? null : Instant.parse(at), operation, resource, user, ip, agent, description);
    }

    private static List<AuditChain.Entry> hashCases() {
        String longText = "é".repeat(300);
        return List.of(
                entry(null, "2026-10-17T08:00:00.123Z", "LOGIN_SUCCESS", "admin", "admin", "203.0.113.9",
                        "Mozilla/5.0", "Signed in."),
                entry("a".repeat(64), "2026-10-17T08:00:00Z", "SETTING_UPDATED", "sast_enabled", "ciso", null, null,
                        "Setting sast_enabled changed."),
                // Absent and empty hash alike: both mean "no value".
                entry(null, "2026-10-17T08:00:00.100Z", "USER_CREATED", "null", null, "", "", ""),
                entry(null, "2026-10-17T08:00:00.100Z", "USER_CREATED", "null", "", null, null, null),
                // The fraction at every precision an engine returns: written as three digits, truncated.
                entry(null, "2026-10-17T08:00:00.123456Z", "LOGIN_FAILURE", "x", "x", null, null, "micro"),
                entry(null, "2026-10-17T08:00:00.123456789Z", "LOGIN_FAILURE", "x", "x", null, null, "nano"),
                entry(null, "2026-10-17T08:00:00.999999999Z", "LOGIN_FAILURE", "x", "x", null, null, "rounding down"),
                entry(null, "2026-10-17T08:00:00.000001Z", "LOGIN_FAILURE", "x", "x", null, null, "a microsecond"),
                entry(null, "1970-01-01T00:00:00Z", "LOGIN_FAILURE", "x", "x", null, null, "epoch"),
                entry(null, "1969-12-31T23:59:59.999Z", "LOGIN_FAILURE", "x", "x", null, null, "before the epoch"),
                entry(null, "0001-01-01T00:00:00Z", "LOGIN_FAILURE", "x", "x", null, null, "year one"),
                entry(null, "9999-12-31T23:59:59.999Z", "LOGIN_FAILURE", "x", "x", null, null, "year 9999"),
                entry(null, null, "LOGIN_FAILURE", "x", "x", null, null, "no instant"),
                // Text outside ASCII, outside the BMP, a NUL inside a value, line breaks.
                entry(null, "2026-10-17T08:00:00.001Z", "ISSUE_TRIAGED", "repo:12/issue:7", "dévelopeur",
                        "2001:db8::1", "agent \"quoted\" \\ back", "Accepté — 🛡️ risk\u0000 noted\nline two\r\n"),
                entry(null, "2026-10-17T08:00:00.002Z", "ISSUE_TRIAGED", "r", "u", null, null, longText),
                // A field boundary cannot be imitated: these two differ only by where the text sits.
                entry(null, "2026-10-17T08:00:00.003Z", "A", "b", "c", null, null, "d"),
                entry(null, "2026-10-17T08:00:00.003Z", "A", "bc", "", null, null, "d"));
    }

    private static ObjectNode write(ObjectNode node, AuditChain.Entry entry) {
        node.put("previousHash", entry.previousHash());
        node.put("timestamp", entry.timestamp() == null ? null : entry.timestamp().toString());
        node.put("operationType", entry.operationType());
        node.put("resourceId", entry.resourceId());
        node.put("userId", entry.userId());
        node.put("ipAddress", entry.ipAddress());
        node.put("userAgent", entry.userAgent());
        node.put("description", entry.description());
        return node;
    }

    private static AuditChain.VerifiableEntry chained(String id, AuditChain.Entry entry) {
        return new AuditChain.VerifiableEntry(id, AuditChain.computeEntryHash(entry), entry);
    }

    private static AuditChain.Entry relinked(AuditChain.Entry entry, String previous) {
        return new AuditChain.Entry(previous, entry.timestamp(), entry.operationType(), entry.resourceId(),
                entry.userId(), entry.ipAddress(), entry.userAgent(), entry.description());
    }

    /** A chain of three, each onto the one before. */
    private static List<AuditChain.VerifiableEntry> intact() {
        List<AuditChain.VerifiableEntry> log = new ArrayList<>();
        String previous = null;
        for (int i = 1; i <= 3; i++) {
            AuditChain.Entry entry = relinked(
                    entry(null, "2026-10-17T08:00:0" + i + ".000Z", "LOGIN_SUCCESS", "u" + i, "u" + i, null, null,
                            "entry " + i),
                    previous);
            AuditChain.VerifiableEntry chainedEntry = chained("id-" + i, entry);
            log.add(chainedEntry);
            previous = chainedEntry.entryHash();
        }
        return log;
    }

    private record Case(String name, List<AuditChain.VerifiableEntry> entries) {}

    private static List<Case> verificationCases() {
        List<Case> cases = new ArrayList<>();
        cases.add(new Case("empty", List.of()));
        cases.add(new Case("intact", intact()));

        List<AuditChain.VerifiableEntry> modified = new ArrayList<>(intact());
        AuditChain.VerifiableEntry second = modified.get(1);
        AuditChain.Entry altered = new AuditChain.Entry(second.entry().previousHash(), second.entry().timestamp(),
                second.entry().operationType(), second.entry().resourceId(), second.entry().userId(),
                second.entry().ipAddress(), second.entry().userAgent(), "entry 2, edited");
        modified.set(1, new AuditChain.VerifiableEntry(second.id(), second.entryHash(), altered));
        cases.add(new Case("a field changed", modified));

        List<AuditChain.VerifiableEntry> deleted = new ArrayList<>(intact());
        deleted.remove(1);
        cases.add(new Case("an entry somebody descends from deleted", deleted));

        List<AuditChain.VerifiableEntry> tip = new ArrayList<>(intact());
        tip.remove(2);
        cases.add(new Case("the tip deleted, which nothing can see", tip));

        // Two branches: two instances that read the same head. Legitimate.
        List<AuditChain.VerifiableEntry> forked = new ArrayList<>(intact());
        String head = forked.get(2).entryHash();
        forked.add(chained("id-4a", relinked(entry(null, "2026-10-17T08:00:04.000Z", "A", "x", "x", null, null, "4a"), head)));
        forked.add(chained("id-4b", relinked(entry(null, "2026-10-17T08:00:04.000Z", "A", "x", "x", null, null, "4b"), head)));
        cases.add(new Case("a fork", forked));

        // Rows from before the chaining: counted, not reported — unless dated after it started.
        List<AuditChain.VerifiableEntry> inherited = new ArrayList<>();
        inherited.add(new AuditChain.VerifiableEntry("old-1", null,
                entry(null, "2026-10-17T07:00:00.000Z", "LOGIN_SUCCESS", "x", "x", null, null, "before")));
        inherited.add(new AuditChain.VerifiableEntry("old-2", "",
                entry(null, "2026-10-17T08:00:01.000Z", "LOGIN_SUCCESS", "x", "x", null, null, "same instant")));
        inherited.addAll(intact());
        cases.add(new Case("rows from before the chaining", inherited));

        List<AuditChain.VerifiableEntry> planted = new ArrayList<>(intact());
        planted.add(new AuditChain.VerifiableEntry("planted", null,
                entry(null, "2026-10-17T08:00:02.500Z", "LOGIN_SUCCESS", "x", "x", null, null, "by hand")));
        cases.add(new Case("a row without a hash after the chaining began", planted));

        List<AuditChain.VerifiableEntry> undated = new ArrayList<>(intact());
        undated.add(new AuditChain.VerifiableEntry("undated", null,
                entry(null, null, "LOGIN_SUCCESS", "x", "x", null, null, "no instant")));
        cases.add(new Case("a row without a hash nor an instant", undated));

        List<AuditChain.VerifiableEntry> onlyOld = List.of(new AuditChain.VerifiableEntry("old", null,
                entry(null, "2026-10-17T07:00:00.000Z", "LOGIN_SUCCESS", "x", "x", null, null, "before")));
        cases.add(new Case("only rows from before the chaining", onlyOld));

        // The first break reported is the first in the list's order, whichever rule it breaks.
        List<AuditChain.VerifiableEntry> twoBreaks = new ArrayList<>(deleted);
        AuditChain.VerifiableEntry first = twoBreaks.get(0);
        twoBreaks.set(0, new AuditChain.VerifiableEntry(first.id(), "f".repeat(64), first.entry()));
        cases.add(new Case("two breaks, the first reported", twoBreaks));
        return cases;
    }

    private static ArrayNode entries(ArrayNode array, List<AuditChain.VerifiableEntry> entries) {
        for (AuditChain.VerifiableEntry entry : entries) {
            ObjectNode node = array.addObject();
            node.put("id", entry.id());
            node.put("entryHash", entry.entryHash());
            write(node.putObject("entry"), entry.entry());
        }
        return array;
    }

    @Test
    void theHashesTheVerificationsAndTheRebuildsThisSideAnswers() throws Exception {
        ObjectNode set = JSON.createObjectNode();
        ArrayNode hashes = set.putArray("hashes");
        for (AuditChain.Entry entry : hashCases()) {
            ObjectNode node = hashes.addObject();
            write(node.putObject("entry"), entry);
            node.put("canonical", entry.timestamp() == null ? null : Digests.canonical(entry.timestamp()));
            node.put("hash", AuditChain.computeEntryHash(entry));
        }
        ArrayNode verifications = set.putArray("verifications");
        for (Case verification : verificationCases()) {
            ObjectNode node = verifications.addObject();
            node.put("name", verification.name());
            entries(node.putArray("entries"), verification.entries());
            AuditChain.Verification result = AuditChain.verifyChain(verification.entries());
            node.put("broken", result.broken());
            node.put("unverifiable", result.unverifiable());
        }
        ArrayNode rebuilds = set.putArray("rebuilds");
        for (Case rebuild : verificationCases()) {
            ObjectNode node = rebuilds.addObject();
            node.put("name", rebuild.name());
            entries(node.putArray("entries"), rebuild.entries());
            entries(node.putArray("rebuilt"), AuditChain.rebuildChain(rebuild.entries()));
        }
        ReferenceSet.expect("audit/chain.json", JSON.writeValueAsString(set) + "\n");
    }

    /** The column's values, in declaration order: what an entry may say it is. */
    @Test
    void theOperationsAndTheirWireNames() {
        ReferenceSet.expect("audit/operations.txt", Arrays.stream(AuditOperation.values())
                .map(operation -> operation.name() + "\t" + operation.wireName())
                .collect(Collectors.joining("\n", "", "\n")));
    }
}

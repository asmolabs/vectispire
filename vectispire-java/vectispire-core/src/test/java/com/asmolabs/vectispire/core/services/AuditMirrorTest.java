package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The second copy, and the one thing the chain cannot do without it.
 *
 * <p><b>The case that matters is the third test.</b> The chain detects a modified entry, because
 * its hash stops matching, and it detects a deleted middle entry, because whoever descends from
 * it points at nothing. It cannot detect the deletion of an entry <em>nobody descends from</em>
 * — the last one written, which is precisely the entry somebody covering their tracks removes.
 * `03-security.md` records that as an accepted limit. With a mirror it is one subtraction.
 */
@DisplayName("the audit mirror")
class AuditMirrorTest {

    private static final Instant NOW = Instant.parse("2026-08-21T10:00:00Z");

    @TempDir
    Path scratch;

    private final ObjectMapper json = new ObjectMapper();
    private final List<AuditLogEntity> rows = new ArrayList<>();

    private Path mirrorFile;
    private AuditLog entries;
    private AuditLogService service;

    @BeforeEach
    void wire() {
        rows.clear();
        mirrorFile = scratch.resolve("nested").resolve("audit.ndjson");
        entries = auditLogOver(rows);
        service = new AuditLogService(entries, new FileAuditMirror(mirrorFile, json), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    /**
     * The repository reduced to append and read-back-in-write-order, as its neighbour suite does
     * it: the identifier is assigned on save because the column is generated, and a fake that
     * left it null would test a row shape production never produces.
     */
    private static AuditLog auditLogOver(List<AuditLogEntity> rows) {
        AuditLog repository = mock(AuditLog.class);
        when(repository.save(any())).thenAnswer(call -> {
            AuditLogEntity row = call.getArgument(0);
            row.setId(UUID.randomUUID());
            rows.add(row);
            return row;
        });
        when(repository.findTopByOrderByTimestampDescIdDesc())
                .thenAnswer(call -> rows.isEmpty() ? Optional.empty() : Optional.of(rows.getLast()));
        when(repository.findAllByOrderByTimestampAscIdAsc()).thenAnswer(call -> List.copyOf(rows));
        return repository;
    }

    @Test
    @DisplayName("every entry is appended as one line, in a directory it creates")
    void entriesAreMirrored() {
        record(3);

        // The directory did not exist: an operator pointing the mirror at a path under a volume
        // should not have to create it first, and failing on the first entry is the worst moment
        // to discover that.
        assertThat(mirrorFile).exists();
        assertThat(lines()).hasSize(3);
        assertThat(service.verifyAgainstMirror())
                .returns(true, AuditLogService.MirrorComparison::configured)
                .returns(0, AuditLogService.MirrorComparison::missingFromTable)
                .returns(0, AuditLogService.MirrorComparison::missingFromMirror);
    }

    @Test
    @DisplayName("what is written is comparable with the table, field by field")
    void theMirroredLineCarriesTheChain() throws Exception {
        record(1);

        var line = json.readTree(lines().getFirst());
        AuditLogEntity row = rows.getFirst();
        assertThat(line.path("entryHash").asText()).isEqualTo(row.getEntryHash());
        assertThat(line.path("operation").asText()).isEqualTo(row.getOperationType());
        assertThat(line.path("userId").asText()).isEqualTo("alice");
        // The instant is written in the canonical form the hash uses, not `Instant::toString`:
        // the two differ on an instant landing exactly on the second, and a mirror that printed
        // it differently would invite a comparison that reports a difference which is not one.
        assertThat(line.path("timestamp").asText()).isEqualTo("2026-08-21T10:00:00.000Z");
    }

    @Test
    @DisplayName("the deletion the chain cannot see is one subtraction here")
    void aDeletedTailIsDetected() {
        record(3);
        // The last entry, removed from the table only — the mirror keeps its line. Nothing
        // descends from it, so the chain is still perfect: this is the exact case the security
        // document records as accepted, and the reason the mirror exists.
        rows.removeLast();

        assertThat(AuditChain.verifyChain(verifiable()).broken())
                .as("the chain alone still declares the log intact")
                .isNull();
        assertThat(service.verifyAgainstMirror().missingFromTable())
                .as("and the mirror knows one entry is gone")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("an entry inserted into the table alone is reported too")
    void anUnmirroredInsertIsDetected() {
        record(2);
        // Somebody with the database and not the file. The chain accepts it if they recomputed
        // the hashes; the mirror never saw it.
        AuditLogEntity forged = new AuditLogEntity();
        forged.setId(UUID.randomUUID());
        forged.setTimestamp(NOW.plusSeconds(10));
        forged.setOperationType("LOGIN_SUCCESS");
        forged.setResourceId("root");
        forged.setEntryHash("a-hash-the-mirror-never-saw");
        rows.add(forged);

        assertThat(service.verifyAgainstMirror().missingFromMirror()).isEqualTo(1);
    }

    @Test
    @DisplayName("no mirror configured is a state, not a clean bill of health")
    void aDisabledMirrorSaysSo() {
        AuditLogService withoutMirror = new AuditLogService(
                auditLogOver(rows), new AuditMirror.Disabled(), Clock.fixed(NOW, ZoneOffset.UTC));
        withoutMirror.record(AuditLogService.Record.of(AuditOperation.LOGIN_SUCCESS, "alice", "in", "alice"));

        assertThat(withoutMirror.verifyAgainstMirror())
                .returns(false, AuditLogService.MirrorComparison::configured)
                // Zero and zero — which is why `configured` has to travel with them. Read alone
                // they say "nothing is missing" about a comparison that never happened.
                .returns(0, AuditLogService.MirrorComparison::missingFromTable)
                .returns(0, AuditLogService.MirrorComparison::missingFromMirror);
    }

    private void record(int count) {
        for (int i = 0; i < count; i++) {
            service.record(AuditLogService.Record.of(
                    AuditOperation.SETTING_UPDATED, "sast_enabled", "changed " + i, "alice"));
        }
    }

    private List<String> lines() {
        try {
            return Files.readAllLines(mirrorFile).stream().filter(line -> !line.isBlank()).toList();
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    private List<AuditChain.VerifiableEntry> verifiable() {
        return rows.stream()
                .map(row -> new AuditChain.VerifiableEntry(
                        row.getId().toString(),
                        row.getEntryHash(),
                        new AuditChain.Entry(
                                row.getPreviousHash(),
                                row.getTimestamp(),
                                row.getOperationType(),
                                row.getResourceId(),
                                row.getUserId(),
                                row.getIpAddress(),
                                row.getUserAgent(),
                                row.getDescription())))
                .toList();
    }

}

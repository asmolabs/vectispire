package com.asmolabs.vectispire.core.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.audit.internal.AuditMirror;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the audit log's integrity chain")
class AuditLogServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T10:00:00Z");

    private final List<AuditLogEntity> stored = new ArrayList<>();
    private AuditLogRepository entries;
    private AuditLogService service;

    @BeforeEach
    void wire() {
        stored.clear();
        entries = mock(AuditLogRepository.class);
        // No mirror here on purpose: this suite is about the chain the table carries. The
        // second copy has its own suite, and mixing the two would make a chain failure and a
        // mirror failure look alike.
        service = new AuditLogService(entries, new AuditMirror.Disabled(), Clock.fixed(NOW, ZoneOffset.UTC), java.util.List.of(),
                org.springframework.transaction.support.TransactionOperations.withoutTransaction());

        // The fake assigns an identifier, because the database does: the column is
        // `@GeneratedValue`, and a fake that leaves it null tests a row shape production never
        // produces — then fails on the read path for a reason that has nothing to do with the
        // chain.
        when(entries.saveAndFlush(any())).thenAnswer(call -> {
            AuditLogEntity row = call.getArgument(0);
            row.setId(UUID.randomUUID());
            stored.add(row);
            return row;
        });
        when(entries.findTopByOrderByTimestampDescIdDesc())
                .thenAnswer(call -> stored.stream().max(Comparator.comparing(AuditLogEntity::getTimestamp)));
        when(entries.findAllByOrderByTimestampAscIdAsc())
                .thenAnswer(call -> stored.stream()
                        .sorted(Comparator.comparing(AuditLogEntity::getTimestamp)
                                .thenComparing(row -> row.getId().toString()))
                        .toList());
    }

    @Test
    @DisplayName("entries written in the same millisecond still verify")
    void aTightLoopDoesNotBreakTheChain() {
        // The clock is fixed, which is the worst case and the one that produced the defect: five
        // entries at the same instant were built in one order and read back in another, and
        // verification failed on a perfectly intact log.
        for (int i = 0; i < 5; i++) {
            service.record(AuditLogService.Record.of(AuditOperation.SETTING_UPDATED, "sast_enabled", "on", "alice"));
        }

        assertThat(stored).extracting(AuditLogEntity::getTimestamp).doesNotHaveDuplicates();
        assertThat(service.verify()).returns(null, AuditChain.Verification::broken);
    }

    @Test
    @DisplayName("an altered description is detected")
    void tamperingBreaksTheChain() {
        service.record(AuditLogService.Record.of(AuditOperation.USER_DELETED, "bob", "Account deleted", "alice"));
        service.record(AuditLogService.Record.of(AuditOperation.LOGIN_SUCCESS, "alice", "Login succeeded", "alice"));

        stored.getFirst().setDescription("Account archived");

        assertThat(service.verify().broken()).isNotNull();
    }

    @Test
    @DisplayName("a write failure never fails the action being described")
    void aFullTableDoesNotStopAnAdministratorLoggingIn() {
        org.mockito.Mockito.reset(entries);
        when(entries.findTopByOrderByTimestampDescIdDesc()).thenReturn(Optional.empty());
        when(entries.saveAndFlush(any())).thenThrow(new IllegalStateException("disk full"));

        // No exception: the opposite would give a full table the power to block authentication.
        service.record(AuditLogService.Record.of(AuditOperation.LOGIN_SUCCESS, "alice", "Login succeeded", "alice"));
    }

    @Test
    @DisplayName("an over-long description costs its tail, not the entry")
    void descriptionsAreTruncatedRatherThanRefused() {
        service.record(AuditLogService.Record.of(AuditOperation.ISSUE_TRIAGED, "42", "x".repeat(400), "alice"));

        assertThat(stored).singleElement().extracting(AuditLogEntity::getDescription)
                .asString()
                .hasSize(255);
    }

    @Test
    @DisplayName("every bounded column is cut to its width, and the entry still verifies")
    void everyBoundedColumnIsTruncated() {
        service.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                "k".repeat(1000),
                "d".repeat(1000),
                "u".repeat(1000),
                "1".repeat(200),
                "a".repeat(1000)));

        assertThat(stored).singleElement().satisfies(row -> {
            assertThat(row.getResourceId()).hasSize(255);
            assertThat(row.getDescription()).hasSize(255);
            assertThat(row.getUserId()).hasSize(255);
            assertThat(row.getIpAddress()).hasSize(64);
            assertThat(row.getUserAgent()).hasSize(255);
        });
        assertThat(service.verify()).returns(null, AuditChain.Verification::broken);
    }

    @Test
    @DisplayName("a cut never splits a surrogate pair")
    void aCutKeepsWholeCharacters() {
        // U+1F600 is two UTF-16 units; placed across the boundary, a naive cut keeps half of it.
        service.record(AuditLogService.Record.of(
                AuditOperation.SETTING_UPDATED, "r", "x".repeat(254) + "\uD83D\uDE00", "alice"));

        assertThat(stored).singleElement().extracting(AuditLogEntity::getDescription)
                .isEqualTo("x".repeat(254));
    }

    @Test
    void anEmptyIpOrAgentIsStoredAsAbsent() {
        service.record(new AuditLogService.Record(AuditOperation.ACCESS_DENIED, "/api/users", "Refused", "bob", "", "  "));

        assertThat(stored).singleElement().satisfies(row -> {
            assertThat(row.getIpAddress()).isNull();
            assertThat(row.getUserAgent()).isNull();
        });
    }

    @Test
    @DisplayName("the first entry chains onto nothing")
    void theFirstEntryHasNoPredecessor() {
        service.record(AuditLogService.Record.of(AuditOperation.USER_CREATED, "alice", "Created", null));

        assertThat(stored).singleElement().satisfies(row -> {
            assertThat(row.getPreviousHash()).isNull();
            assertThat(row.getEntryHash()).isNotBlank();
        });
    }

    @Test
    void eachEntryChainsOntoTheOneBefore() {
        service.record(AuditLogService.Record.of(AuditOperation.USER_CREATED, "alice", "Created", null));
        service.record(AuditLogService.Record.of(AuditOperation.USER_UPDATED, "alice", "Renamed", null));

        assertThat(stored.get(1).getPreviousHash()).isEqualTo(stored.getFirst().getEntryHash());
    }

    @Test
    @DisplayName("no predecessor is found when the table is empty")
    void handlesAnEmptyTable() {
        when(entries.findTopByOrderByTimestampDescIdDesc()).thenReturn(Optional.empty());

        service.record(AuditLogService.Record.of(AuditOperation.SCAN_TRIGGERED, "7", "Manual scan", "alice"));

        assertThat(stored).hasSize(1);
    }
}

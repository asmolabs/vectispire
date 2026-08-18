package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.audit.AuditChain;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import com.asmolabs.zanshin.core.repositories.Repositories;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the audit log's integrity chain")
class AuditLogServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T10:00:00Z");

    private final List<AuditLogEntity> stored = new ArrayList<>();
    private Repositories.AuditLog entries;
    private AuditLogService service;

    @BeforeEach
    void wire() {
        stored.clear();
        entries = mock(Repositories.AuditLog.class);
        service = new AuditLogService(entries, Clock.fixed(NOW, ZoneOffset.UTC));

        when(entries.save(any())).thenAnswer(call -> {
            stored.add(call.getArgument(0));
            return call.getArgument(0);
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
        when(entries.save(any())).thenThrow(new IllegalStateException("disk full"));

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

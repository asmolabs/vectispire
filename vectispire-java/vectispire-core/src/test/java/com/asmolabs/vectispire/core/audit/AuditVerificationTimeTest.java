package com.asmolabs.vectispire.core.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

/**
 * The instant a verification of the audit chain states is the server's.
 *
 * <p>The attestation screen dated "the state established at" from the browser's clock — the hour a page
 * was opened on somebody's machine, set to whatever its owner likes — and not the hour the chain was found
 * intact. The check now says when it ran, by the clock every other recorded instant here reads.
 */
@DisplayName("a verification of the audit chain")
class AuditVerificationTimeTest {

    @Test
    @DisplayName("is dated by the server's clock")
    void datedByTheServer() {
        Instant then = Instant.parse("2026-10-13T08:15:30Z");
        AuditLogService log = mock(AuditLogService.class);
        when(log.verify()).thenReturn(new AuditChain.Verification(null, 0));
        when(log.verifyAgainstMirror()).thenReturn(new AuditLogService.MirrorComparison(false, 0, 0));
        AuditLogRepository entries = mock(AuditLogRepository.class);
        when(entries.count()).thenReturn(4L);

        AuditLogQueryService.Integrity integrity = new AuditLogQueryService(
                        entries, log, mock(ApplicationEventPublisher.class), Clock.fixed(then, ZoneOffset.UTC))
                .verify();

        assertThat(integrity.checkedAt()).isEqualTo(then);
        assertThat(integrity.intact()).isTrue();
    }
}

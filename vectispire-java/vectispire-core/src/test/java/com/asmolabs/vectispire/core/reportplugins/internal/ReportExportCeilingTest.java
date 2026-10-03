package com.asmolabs.vectispire.core.reportplugins.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import java.util.OptionalLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The export bound a report run is built under, from the database's largest statement: half of it, the margin
 * aside, never above the standard 64 MiB. That the result is what MySQL stores is {@code
 * ReportRunQueueIntegrationTest}'s, on the server.
 */
@DisplayName("the export ceiling of a report run")
class ReportExportCeilingTest {

    private static final long MIB = 1024 * 1024;
    private static final long STANDARD = ProjectExportBounds.STANDARD.maxJsonBytes();

    @Test
    @DisplayName("no ceiling below the standard bound on PostgreSQL; half MySQL's packet, less the margin")
    void storable() {
        assertThat(ReportExportCeiling.storable(OptionalLong.empty())).isEqualTo(STANDARD);
        assertThat(ReportExportCeiling.storable(OptionalLong.of(64 * MIB)))
                .isEqualTo((64 * MIB - ReportExportCeiling.STATEMENT_MARGIN) / 2);
        assertThat(ReportExportCeiling.storable(OptionalLong.of(4 * MIB))).as("MySQL 5.7's default").isLessThan(2 * MIB);
        assertThat(ReportExportCeiling.storable(OptionalLong.of(1024 * MIB))).isEqualTo(STANDARD);
    }

    @Test
    @DisplayName("the packet the refusal names restores the standard bound")
    void theAdviceHolds() {
        assertThat(ReportExportCeiling.RAISED_PACKET).isEqualTo("160M");
        assertThat(ReportExportCeiling.storable(OptionalLong.of(160 * MIB))).isEqualTo(STANDARD);
    }

    @Test
    @DisplayName("a refusal under a lowered bound says why and what restores it; under the standard one, nothing more")
    void why() {
        assertThat(ReportExportCeiling.why(ProjectExportBounds.STANDARD)).isEmpty();
        assertThat(ReportExportCeiling.why(new ProjectExportBounds(32 * MIB, 100_000, 100_000)))
                .contains("max_allowed_packet")
                .contains(String.valueOf(32 * MIB))
                .contains("160M");
    }
}

package com.asmolabs.vectispire.core.agents.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.LongStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The repair's audit entry. The trail truncates a description at its column, so an entry listing
 * scans past it would end on half an identifier — another scan's, as far as a reader can tell.
 */
@DisplayName("the entry the withheld-claim repair writes")
class WithheldClaimRepairTest {

    @Test
    @DisplayName("lists whole identifiers while they fit, then counts the rest, within the column")
    void staysInsideTheColumn() {
        List<Long> many = LongStream.rangeClosed(1_000_000, 1_000_200).boxed().toList();

        String entry = WithheldClaimRepair.describe(many);

        assertThat(entry).hasSizeLessThanOrEqualTo(WithheldClaimRepair.DESCRIPTION_LENGTH)
                .contains("201 waiting scan(s)")
                .contains("1000000, 1000001")
                .endsWith(" more.");
        int listed = entry.substring(entry.indexOf("Scans: ")).split(",").length;
        assertThat(entry).endsWith(" and " + (many.size() - listed) + " more.");
    }

    @Test
    @DisplayName("names every scan when they all fit")
    void namesThemAll() {
        assertThat(WithheldClaimRepair.describe(List.of(7L, 12L))).endsWith("Scans: 7, 12.");
    }
}

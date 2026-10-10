package com.asmolabs.vectispire.core.reportplugins;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the targets a report run's export carried (decision 0042)")
class ReportRunTargetsTest {

    private static final ScanTarget REPO = new ScanTarget.Repository(12);
    private static final ScanTarget IMAGE = new ScanTarget.Container(4);

    private static VisibilityService.Allowance seeing(ScanTarget... targets) {
        return new VisibilityService.Allowance(Visibility.only(List.of(targets)), Set.of());
    }

    private static final VisibilityService.Allowance EVERYTHING =
            new VisibilityService.Allowance(Visibility.everything(), Set.of());

    @Test
    @DisplayName("recorded as an issue's fingerprint names each target, and read back")
    void roundTrip() {
        String recorded = ReportRunTargets.record(List.of(REPO, IMAGE));

        assertThat(recorded).isEqualTo("repo:12 container:4");
        assertThat(ReportRunTargets.parse(recorded)).contains(List.of(REPO, IMAGE));
    }

    @Test
    @DisplayName("a reader must see every target, the image as well as the repository")
    void everyTarget() {
        String recorded = ReportRunTargets.record(List.of(REPO, IMAGE));

        assertThat(ReportRunTargets.seenBy(recorded, seeing(REPO, IMAGE))).isTrue();
        assertThat(ReportRunTargets.seenBy(recorded, seeing(REPO))).isFalse();
        assertThat(ReportRunTargets.seenBy(recorded, seeing(new ScanTarget.Container(12)))).isFalse();
    }

    @Test
    @DisplayName("an export over no target asks nothing more than the project; one not recorded asks everything")
    void emptyIsNotAbsent() {
        assertThat(ReportRunTargets.seenBy("", seeing())).isTrue();
        assertThat(ReportRunTargets.seenBy(null, seeing(REPO, IMAGE))).isFalse();
        assertThat(ReportRunTargets.seenBy(null, EVERYTHING)).isTrue();
        assertThat(ReportRunTargets.seenBy(null,
                new VisibilityService.Allowance(Visibility.everything(), Set.of(), true)))
                .as("a narrowed credential never reads what nobody recorded").isFalse();
    }

    @Test
    @DisplayName("text that does not parse is read as not recorded, never as fewer targets")
    void malformedIsNotRecorded() {
        for (String malformed : List.of("repo:12 image:4", "repo:x", "repo12", "repo:12 container:")) {
            assertThat(ReportRunTargets.parse(malformed)).as(malformed).isEmpty();
            assertThat(ReportRunTargets.seenBy(malformed, seeing(REPO, IMAGE))).as(malformed).isFalse();
        }
    }
}

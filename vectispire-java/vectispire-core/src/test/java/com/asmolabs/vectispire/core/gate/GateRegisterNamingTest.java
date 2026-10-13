package com.asmolabs.vectispire.core.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The second lock on a register row's name.
 *
 * <p>The route cannot show it holds: a restricted reader's read selects their targets in SQL and the
 * page filters again by {@code Visibility.permits}, so a row of somebody else's never reaches the
 * naming. Should either lock ever be loosened, the name is the first thing the row would give away.
 */
@DisplayName("a register row's target name")
class GateRegisterNamingTest {

    private static final TargetNaming.Names NAMES =
            new TargetNaming.Names(Map.of(1L, "mine", 2L, "theirs"), Map.of(3L, "team/ledger:1.0"));

    @Test
    @DisplayName("is given for a target the reader may see, repository or image")
    void givenWhenVisible() {
        assertThat(GateRegisterService.nameOf(row(1L, null), NAMES, Visibility.everything())).isEqualTo("mine");
        assertThat(GateRegisterService.nameOf(row(null, 3L), NAMES, Visibility.everything()))
                .isEqualTo("team/ledger:1.0");
        assertThat(GateRegisterService.nameOf(
                        row(1L, null), NAMES, Visibility.only(List.of(new ScanTarget.Repository(1)))))
                .isEqualTo("mine");
    }

    @Test
    @DisplayName("is withheld for a target the reader may not see")
    void withheldWhenHidden() {
        assertThat(GateRegisterService.nameOf(
                        row(2L, null), NAMES, Visibility.only(List.of(new ScanTarget.Repository(1)))))
                .isNull();
    }

    @Test
    @DisplayName("is null for a verdict that names no target")
    void nullWithoutTarget() {
        assertThat(GateRegisterService.nameOf(row(null, null), NAMES, Visibility.everything())).isNull();
    }

    private static GateVerdictView row(Long repoId, Long containerId) {
        return new GateVerdictView(
                UUID.randomUUID(), repoId, containerId, true, 1, 0, 0, 0, 0, 0, null, "GLOBAL", null, false,
                Instant.parse("2026-10-13T08:00:00Z"), "ci", null);
    }
}

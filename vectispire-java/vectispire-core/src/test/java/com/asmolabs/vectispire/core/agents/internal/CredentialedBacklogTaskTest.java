package com.asmolabs.vectispire.core.agents.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.asmolabs.vectispire.core.agents.CredentialedBacklog;
import com.asmolabs.vectispire.core.agents.internal.CredentialedBacklogTask.Say;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * When the warning is said. Every minute would teach an operator to silence the logger; never again
 * after the first would leave a log whose last word about a state lasting days is days old.
 */
@DisplayName("the warning about scans nobody able to be handed a credential can take")
class CredentialedBacklogTaskTest {

    private static final Instant T0 = Instant.parse("2026-09-27T10:00:00Z");

    private final CredentialedBacklogTask task =
            new CredentialedBacklogTask(mock(CredentialedBacklog.class), Clock.systemUTC());

    private static CredentialedBacklog.Unserved waiting(long scans) {
        return new CredentialedBacklog.Unserved(scans, List.of(""), List.of("edge"));
    }

    @Test
    @DisplayName("said at once, then quiet for a quarter of an hour, then said again while it lasts")
    void rateLimited() {
        assertThat(task.decide(waiting(3), T0)).isEqualTo(Say.WARNING);
        assertThat(task.decide(waiting(3), T0.plusSeconds(60))).isEqualTo(Say.NOTHING);
        assertThat(task.decide(waiting(3), T0.plus(CredentialedBacklogTask.QUIET).minusSeconds(1))).isEqualTo(Say.NOTHING);
        assertThat(task.decide(waiting(3), T0.plus(CredentialedBacklogTask.QUIET))).isEqualTo(Say.WARNING);
    }

    @Test
    @DisplayName("said again when more scans are waiting, and once when none are")
    void growthAndClearing() {
        assertThat(task.decide(waiting(1), T0)).isEqualTo(Say.WARNING);
        assertThat(task.decide(waiting(2), T0.plusSeconds(60))).isEqualTo(Say.WARNING);
        assertThat(task.decide(waiting(1), T0.plusSeconds(120))).isEqualTo(Say.NOTHING);

        assertThat(task.decide(CredentialedBacklog.Unserved.NONE, T0.plusSeconds(180))).isEqualTo(Say.CLEARED);
        assertThat(task.decide(CredentialedBacklog.Unserved.NONE, T0.plusSeconds(240))).isEqualTo(Say.NOTHING);
        // A new episode is said at once, quiet period or not.
        assertThat(task.decide(waiting(1), T0.plusSeconds(300))).isEqualTo(Say.WARNING);
    }

    @Test
    @DisplayName("nothing waiting, nothing said")
    void silentWhenHealthy() {
        assertThat(task.decide(CredentialedBacklog.Unserved.NONE, T0)).isEqualTo(Say.NOTHING);
    }
}

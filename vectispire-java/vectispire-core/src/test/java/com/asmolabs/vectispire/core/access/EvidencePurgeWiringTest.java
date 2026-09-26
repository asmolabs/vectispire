package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The evidence the cleanup pass purges reaches it, in the running application.
 *
 * <p><b>The port is only as good as its wiring.</b> The pass used to name the gate's register and
 * the compliance captures itself; since those became their modules' tables it receives whatever
 * implements {@link SessionCleanupService.EvidencePurge}. An implementation Spring does not pick up
 * — a missing {@code @Component}, a package nobody scans — would leave the register growing without
 * a word: the pass would purge the sessions, report nothing wrong, and never be handed the verdicts.
 * {@code EvidenceRetentionTest} cannot see that, because it builds the pass by hand.
 */
@DisplayName("the evidence purge, as wired")
class EvidencePurgeWiringTest extends VectispireContextTest {

    @Autowired
    private List<SessionCleanupService.EvidencePurge> purges;

    @Test
    @DisplayName("hands the cleanup pass both the gate's register and the compliance captures")
    void bothOwnersAreWired() {
        assertThat(purges).extracting(SessionCleanupService.EvidencePurge::label)
                .containsExactlyInAnyOrder("Gate verdict", "Compliance snapshot");
    }
}

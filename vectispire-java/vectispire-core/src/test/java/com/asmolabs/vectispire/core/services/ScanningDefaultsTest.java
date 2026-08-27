package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

/**
 * The scanning defaults a deployment gets without saying anything.
 *
 * <p><b>Written because a threat model described one of them wrongly for months.</b> The STRIDE
 * table's P2 entry mitigated "orchestrator clones an unauthorized repository with the host key"
 * with <em>host SSH disabled by default</em>. The default was, and remains, {@code true}: a
 * repository with no deployment key of its own falls back to the host's {@code ~/.ssh}, which the
 * shipped {@code docker-compose.yml} mounts read-only into the control plane and the agent.
 *
 * <p><b>The value is pinned, not judged.</b> {@code true} is the deliberate choice for the
 * single-team install the default targets, where the operator's key already reaches every target
 * and the alternative was attaching it once per repository. What this test forbids is the value
 * moving in silence — in either direction — while a document somewhere claims the other one.
 *
 * <p>If this fails, the fix is not only the constant. It is the STRIDE model's P2 row and the
 * operational note in {@code ScanningConfiguration}, which describe the posture this value sets.
 */
@DisplayName("the scanning defaults")
class ScanningDefaultsTest extends VectispireContextTest {

    @Value("${vectispire.scanning.host-ssh:true}")
    private boolean hostSsh;

    @Test
    @DisplayName("a repository with no key of its own falls back to the host's, by default")
    void hostSshFallbackIsOnByDefault() {
        assertThat(hostSsh)
                .as("the STRIDE model's P2 row and ScanningConfiguration's note both describe this value; "
                        + "changing it means changing them in the same commit")
                .isTrue();
    }
}

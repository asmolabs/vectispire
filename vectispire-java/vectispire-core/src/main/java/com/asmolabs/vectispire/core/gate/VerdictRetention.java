package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.core.access.SessionCleanupService;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdicts;
import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * The gate's register, purged past the evidence window by the pass that purges the authentication
 * tables.
 *
 * <p><b>A port and not a call</b>, because {@code access} sits below {@code gate}: the pass reached
 * {@code GateVerdicts} directly while the code was packaged by layer, and once the register became
 * this module's table that read closed a cycle between the two. The window, the setting it comes
 * from and the refusal to fail the tick stay where they were, in {@link SessionCleanupService}; this
 * only says which rows go.
 */
@Component
class VerdictRetention implements SessionCleanupService.EvidencePurge {

    private final GateVerdicts verdicts;

    VerdictRetention(GateVerdicts verdicts) {
        this.verdicts = verdicts;
    }

    @Override
    public int deleteBefore(Instant cutoff) {
        return verdicts.deleteBefore(cutoff);
    }

    @Override
    public String label() {
        return "Gate verdict";
    }
}

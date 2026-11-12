package com.asmolabs.vectispire.common.scanning.scanners;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.rust.ScannerRuns;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.Workspace;
import org.junit.jupiter.api.Test;

/**
 * Fixed semgrep container results in, the SAST step's outcome out — for the Rust port's
 * {@code scanners::sast} to match (see {@code ScannerRuns}).
 *
 * <p>The first runs are the pinned image's real output, with the bundled rule and an operator rule
 * set ({@code reference/sast/regenerate.sh}); the rest are edges: the refusal read off stdout, the
 * coverage that makes a report "did not run", the OWASP edition, the severity table. The rule id and
 * the path enter the fingerprint.
 */
class SastReferenceSetTest {

    @Test
    void theOutcomesTheRustPortIsHeldTo() throws Exception {
        ScannerRuns.expectOutcomes("sast", run -> {
            ContainerRunner runner = mock(ContainerRunner.class);
            when(runner.run(any())).thenReturn(new ContainerRunner.ContainerResult(run.stdout(), run.stderr(), run.exitCode()));
            SastScanner scanner = new SastScanner(runner, ScannerImages.PINNED.semgrep());
            return Workspace.withWorkspace(workspace -> scanner.scan(workspace, run.subPath()));
        });
    }
}

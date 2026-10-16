package com.asmolabs.vectispire.common.scanning.scanners;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.rust.ScannerRuns;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.Workspace;
import org.junit.jupiter.api.Test;

/**
 * Fixed checkov container results in, the IaC step's outcome out — for the Rust port's
 * {@code scanners::iac} to match (see {@code ScannerRuns}).
 *
 * <p>The first runs are the pinned image's real output on small trees ({@code reference/iac/regenerate.sh});
 * the rest are edges: an exit code, a document that is not a report, Jackson's leniencies, the path
 * reduction. The check id, the path and the resource enter the fingerprint.
 */
class IacReferenceSetTest {

    @Test
    void theOutcomesTheRustPortIsHeldTo() throws Exception {
        ScannerRuns.expectOutcomes("iac", run -> {
            ContainerRunner runner = mock(ContainerRunner.class);
            when(runner.run(any())).thenReturn(new ContainerRunner.ContainerResult(run.stdout(), run.stderr(), run.exitCode()));
            IacScanner scanner = new IacScanner(runner, ScannerImages.PINNED.checkov());
            return Workspace.withWorkspace(workspace -> scanner.scan(workspace, run.subPath()));
        });
    }
}

package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.Workspace;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

/**
 * Every scanner reads the workspace as its owner, never as root.
 *
 * <p>Root inside a scanner has no capability at all, {@code CAP_DAC_OVERRIDE} included, so it reads
 * only what the permission bits allow — and the workspace is a 0700 directory of Vectispire's user.
 * Four of the five tools ran as root, and in the shipped composition every one of them answered
 * "permission denied" on the workspace. The answer below is what the daemon is asked for; whether the
 * tool then reads the tree is the composition's scan check, in CI.
 */
@DisplayName("the scanners run as the workspace's owner")
class ScannersRunAsWorkspaceOwnerTest {

    private static final ContainerRunner RUNNER = mock(ContainerRunner.class);

    static Stream<Arguments> scanners() {
        return Stream.of(
                Arguments.of("syft, a directory", (Consumer<Workspace>) workspace ->
                        new DependencyScanner(RUNNER, ScannerImages.PINNED, mock(VulnerabilityDatabase.class))
                                .sbomOfDirectory(workspace, null)),
                Arguments.of("syft, an image archive", (Consumer<Workspace>) workspace ->
                        new DependencyScanner(RUNNER, ScannerImages.PINNED, mock(VulnerabilityDatabase.class))
                                .sbomOfImage(workspace, "registry.example/app:1", null)),
                Arguments.of("gitleaks", (Consumer<Workspace>) workspace ->
                        new SecretsScanner(RUNNER, ScannerImages.PINNED.gitleaks()).scan(workspace, null)),
                Arguments.of("checkov", (Consumer<Workspace>) workspace ->
                        new IacScanner(RUNNER, ScannerImages.PINNED.checkov()).scan(workspace, null)),
                Arguments.of("semgrep", (Consumer<Workspace>) workspace ->
                        new SastScanner(RUNNER, ScannerImages.PINNED.semgrep()).scan(workspace, null)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scanners")
    void runsAsTheOwner(String name, Consumer<Workspace> scan) {
        org.mockito.Mockito.reset(RUNNER);
        when(RUNNER.run(any())).thenReturn(new ContainerResult("{}", "", 0));

        String owner = Workspace.withWorkspace(workspace -> {
            try {
                scan.accept(workspace);
            } catch (RuntimeException reportNotReadable) {
                // What the tool would have produced is not the question; what it was run as is.
            }
            return ContainerRun.ownerOf(workspace.root()).orElseThrow();
        });

        ArgumentCaptor<ContainerRun> run = ArgumentCaptor.forClass(ContainerRun.class);
        verify(RUNNER).run(run.capture());
        assertThat(run.getValue().user()).isEqualTo(owner);
        assertThat(run.getValue().asRoot()).isFalse();
    }
}

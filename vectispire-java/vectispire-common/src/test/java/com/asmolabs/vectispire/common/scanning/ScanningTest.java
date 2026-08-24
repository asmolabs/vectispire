package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("scan execution")
class ScanningTest {

    @Nested
    @DisplayName("the workspace")
    class WorkspaceLayout {

        @Test
        @DisplayName("keeps the scanned tree in its own subdirectory")
        void sourceIsNotTheRoot() {
            // Anything Vectispire produces lands at the root, hence outside the analysed tree.
            // Two of those artifacts are actively harmful to feed back in: the secrets report
            // holds every detected secret in the clear, and an SBOM alone exceeds a model
            // review's budget.
            Workspace.withWorkspace(workspace -> {
                assertThat(workspace.source().getParent()).isEqualTo(workspace.root());
                assertThat(workspace.rules().getParent()).isEqualTo(workspace.root());
                assertThat(workspace.source()).isNotEqualTo(workspace.rules());
                return null;
            });
        }

        @Test
        @DisplayName("removes the workspace even when the body throws")
        void cleansUpOnFailure() {
            // Failures are exactly the case where cleanup gets forgotten, and the only one
            // where it really matters: a failed scan leaves a cloned tree and often the
            // secrets report listing what it found.
            AtomicReference<Path> root = new AtomicReference<>();

            assertThatThrownBy(() -> Workspace.withWorkspace(workspace -> {
                        root.set(workspace.root());
                        throw new IllegalStateException("the scan failed");
                    }))
                    .hasMessage("the scan failed");

            assertThat(root.get()).doesNotExist();
        }

        @Test
        @DisplayName("removes a workspace that has files in it")
        void cleansUpNonEmptyTrees() {
            AtomicReference<Path> root = new AtomicReference<>();

            Workspace.withWorkspace(workspace -> {
                try {
                    Files.createDirectories(workspace.source().resolve("nested"));
                    Files.writeString(workspace.source().resolve("nested/file.txt"), "content");
                    root.set(workspace.root());
                } catch (Exception e) {
                    throw new AssertionError(e);
                }
                return null;
            });

            assertThat(root.get()).doesNotExist();
        }

        @Test
        @DisplayName("two workspaces never collide")
        void workspacesAreUnique() {
            // A second scan of the same target must not overwrite the first.
            Path first = Workspace.withWorkspace(Workspace::root);
            Path second = Workspace.withWorkspace(Workspace::root);

            assertThat(first).isNotEqualTo(second);
        }
    }

    @Nested
    @DisplayName("the container specification")
    class RunSpecification {

        @Test
        @DisplayName("starts closed: no network, not root")
        void defaultsAreClosed() {
            // A scanner added six months from now inherits the restrictive shape unless its
            // author argues otherwise.
            ContainerRun run = ContainerRun.of("scanner:1", List.of("--json"), List.of(), "secrets");

            assertThat(run.network()).isFalse();
            assertThat(run.asRoot()).isFalse();
        }

        @Test
        @DisplayName("widening is explicit, and each widening is separate")
        void wideningIsDeliberate() {
            ContainerRun run = ContainerRun.of("scanner:1", List.of(), List.of(), "deps").withNetwork();

            assertThat(run.network()).isTrue();
            assertThat(run.asRoot()).isFalse();
            assertThat(run.runningAsRoot().asRoot()).isTrue();
        }

        @Test
        @DisplayName("a read-only mount says so in the bind")
        void mountsCarryTheirMode() {
            ContainerRun run = ContainerRun.of(
                    "scanner:1",
                    List.of(),
                    List.of(ContainerRun.Mount.readOnly("/tmp/src", "/src"), ContainerRun.Mount.writable("/tmp/out", "/out")),
                    "sast");

            assertThat(run.binds()).containsExactly("/tmp/src:/src:ro", "/tmp/out:/out");
        }

        @Test
        @DisplayName("there is no way to ask for the Docker socket")
        void noSocketOption() {
            // Mounting it is equivalent to root on the host. The previous shape carried an
            // option nobody used any more; an option survives, a missing capability does not.
            assertThat(ContainerRun.class.getRecordComponents())
                    .extracting(java.lang.reflect.RecordComponent::getName)
                    .doesNotContain("dockerSocket");
        }
    }

    @Nested
    @DisplayName("reading a scanner's output")
    class Output {

        @Test
        @DisplayName("an absent result is not an empty one")
        void emptyOutputIsAbsentNotEmpty() {
            // The distinction between "analysed, found nothing" and "not analysed". An empty
            // list resolves every existing issue of that type; an absent result changes
            // nothing (decision 0007).
            assertThat(ContainerRunner.parseJson(new ContainerResult("", "", 0), "sast", List.of(0))).isEmpty();
            assertThat(ContainerRunner.parseJson(new ContainerResult("   \n", "", 0), "sast", List.of(0))).isEmpty();
        }

        @Test
        @DisplayName("unparseable output is absent, not a crash")
        void malformedOutputIsAbsent() {
            assertThat(ContainerRunner.parseJson(new ContainerResult("not json", "", 0), "sast", List.of(0)))
                    .isEmpty();
        }

        @Test
        @DisplayName("an unexpected exit code throws, carrying the scanner's own explanation")
        void unexpectedExitThrows() {
            // Without the scanner's output the operator reads "the scanner failed" and has to
            // guess. Truncated, because a verbose checker produces thousands of lines of which
            // only the first carry the cause.
            assertThatThrownBy(() ->
                            ContainerRunner.parseJson(new ContainerResult("", "config error at line 4", 2), "iac", List.of(0)))
                    .isInstanceOf(ScannerFailureException.class)
                    .hasMessageContaining("iac")
                    .hasMessageContaining("config error at line 4");
        }

        @Test
        @DisplayName("a scanner whose findings mean a non-zero exit is not a failure")
        void acceptedExitCodesAreConfigurable() {
            // Several scanners exit 1 to mean "I found something", which is the normal case
            // and not an error.
            assertThat(ContainerRunner.parseJson(new ContainerResult("[]", "", 1), "secrets", List.of(0, 1)))
                    .isPresent();
        }

        @Test
        @DisplayName("truncates a verbose failure rather than carrying kilobytes")
        void truncatesTheExplanation() {
            assertThatThrownBy(() -> ContainerRunner.parseJson(
                            new ContainerResult("", "x".repeat(5000), 2), "iac", List.of(0)))
                    .hasMessageContaining("x".repeat(2000))
                    .satisfies(e -> assertThat(e.getMessage().length()).isLessThan(2100));
        }

        @Test
        @DisplayName("the timeout says which scanner and for how long")
        void timeoutIsActionable() {
            assertThat(ScannerFailureException.timedOut("sast", Duration.ofMinutes(15)))
                    .satisfies(e -> {
                        assertThat(e.label()).isEqualTo("sast");
                        assertThat(e.getMessage()).contains("900s");
                    });
        }
    }
}

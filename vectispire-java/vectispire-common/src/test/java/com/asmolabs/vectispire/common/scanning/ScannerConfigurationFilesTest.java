package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The target does not configure its own audit.
 *
 * <p>checkov, gitleaks and semgrep each read a file of their own from the tree they analyse — measured
 * on the pinned images, a planted {@code .checkov.yaml}, {@code .gitleaksignore} or {@code
 * .semgrepignore} turned a finding into a clean report, and a clean report resolves the backlog. The
 * scanners themselves are mocked here: what is asserted is what each one <em>would find in the tree
 * at the moment it is started</em>, which is the only thing Vectispire decides. That the pinned images
 * do honour those files, and so that this matters, is what {@code scripts/composition-scan-check.sh}
 * shows by planting them in its fixture and requiring every finding regardless.
 */
@DisplayName("the scanners' configuration files in a scanned tree")
class ScannerConfigurationFilesTest {

    private static final Clock FIXED = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    @Nested
    @DisplayName("are gone before the scanner that reads them starts")
    class BeforeTheScanners {

        @TempDir
        Path root;

        private Workspace workspace;
        private Path bundled;

        /** For each scanner started, the planted files it could still see, by image. */
        private final Map<String, List<String>> seen = new LinkedHashMap<>();

        @BeforeEach
        void tree() throws IOException {
            workspace = new Workspace(root.resolve("ws"), root.resolve("ws/source"), root.resolve("ws/rules"));
            Files.createDirectories(workspace.source().resolve("infra/modules"));
            Files.writeString(workspace.source().resolve("main.tf"), "resource \"aws_s3_bucket\" \"b\" {}\n");
            bundled = root.resolve("bundled");
            Files.createDirectories(bundled.resolve("gitleaks"));
            Files.createDirectories(bundled.resolve("semgrep"));
            Files.writeString(bundled.resolve("gitleaks/gitleaks.toml"), "[extend]\n");
            Files.writeString(bundled.resolve("semgrep/rules.yaml"), "rules: []\n");
        }

        @Test
        @DisplayName("checkov: no .checkov.yaml or .checkov.yml, at the root or in the sub-path it is pointed at")
        void checkov() throws IOException {
            List<Path> planted = plant(
                    ".checkov.yaml", "infra/.checkov.yaml", "infra/.checkov.yml", "infra/modules/.checkov.yml");

            analyse("infra", ScanTask.Step.IAC);

            assertThat(seen).containsKey(ScannerImages.PINNED.checkov());
            assertThat(seen.get(ScannerImages.PINNED.checkov()))
                    .describedAs("a .checkov.yaml in the -d directory skips the checks it names, and runs the "
                            + "Python of the external checks directory it names")
                    .isEmpty();
            assertThat(planted).allSatisfy(file -> assertThat(file).doesNotExist());
        }

        @Test
        @DisplayName("gitleaks: no .gitleaksignore, whatever --config says")
        void gitleaks() throws IOException {
            List<Path> planted = plant(".gitleaksignore", "infra/.gitleaksignore");

            analyse("infra", ScanTask.Step.SECRETS);

            assertThat(seen).containsKey(ScannerImages.PINNED.gitleaks());
            assertThat(seen.get(ScannerImages.PINNED.gitleaks()))
                    .describedAs("the ignore file is read from --source beside the forced --config, and drops "
                            + "the fingerprints it lists")
                    .isEmpty();
            assertThat(planted).allSatisfy(file -> assertThat(file).doesNotExist());
        }

        @Test
        @DisplayName("semgrep: no .semgrepignore at any depth, whatever --no-git-ignore says")
        void semgrep() throws IOException {
            List<Path> planted = plant(".semgrepignore", "infra/.semgrepignore", "infra/modules/.semgrepignore");

            analyse(null, ScanTask.Step.SAST);

            assertThat(seen).containsKey(ScannerImages.PINNED.semgrep());
            assertThat(seen.get(ScannerImages.PINNED.semgrep()))
                    .describedAs("every .semgrepignore of the tree excludes what it lists; sparing one harmless "
                            + "file keeps the run past the zero-files check")
                    .isEmpty();
            assertThat(planted).allSatisfy(file -> assertThat(file).doesNotExist());
        }

        @Test
        @DisplayName("and the tree's other files are still there for them")
        void theRestOfTheTreeStays() throws IOException {
            plant(".checkov.yaml", ".gitleaksignore", ".semgrepignore");

            analyse(null, ScanTask.Step.IAC);

            assertThat(workspace.source().resolve("main.tf")).exists();
        }

        private List<Path> plant(String... names) throws IOException {
            List<Path> planted = new ArrayList<>();
            for (String name : names) {
                Path file = workspace.source().resolve(name);
                Files.createDirectories(file.getParent());
                Files.writeString(file, "planted\n");
                planted.add(file);
            }
            return planted;
        }

        private void analyse(String subPath, ScanTask.Step step) {
            ContainerRunner containers = mock(ContainerRunner.class);
            when(containers.outputBytes()).thenReturn(ScannerLimits.DEFAULT_OUTPUT_BYTES);
            when(containers.run(any())).thenAnswer(invocation -> {
                ContainerRun run = invocation.getArgument(0);
                seen.put(run.image(), plantedNow());
                return new ContainerRunner.ContainerResult("", "", 0);
            });
            ScanRunner runner = new ScanRunner(containers, ScannerImages.PINNED, bundled, hash -> List.of(),
                    new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE, FIXED);

            var repository = new ScanTask.Target.Repository("https://host/p.git", "main", subPath, null);
            runner.analyse(new ScanTask(repository, null, Set.of(step)), repository, workspace, FIXED.instant());
        }

        private List<String> plantedNow() throws IOException {
            try (var walk = Files.walk(workspace.source())) {
                return walk.filter(path -> ScannerConfigurationFiles.NAMES.contains(path.getFileName().toString()))
                        .map(path -> workspace.source().relativize(path).toString())
                        .toList();
            }
        }
    }

    @Nested
    @DisplayName("are removed")
    class Removal {

        @TempDir
        Path root;

        @Test
        @DisplayName("as links, never through them: what a link points to stays, a linked directory is not entered")
        void linksAreNotFollowed() throws IOException {
            Path clone = Files.createDirectories(root.resolve("clone"));
            Path outside = Files.createDirectories(root.resolve("outside"));
            Path kept = Files.writeString(outside.resolve(".semgrepignore"), "outside the clone\n");
            Path keptToo = Files.writeString(outside.resolve(".checkov.yaml"), "outside the clone\n");
            Files.createSymbolicLink(clone.resolve(".semgrepignore"), kept);
            Files.createSymbolicLink(clone.resolve("linked"), outside);

            List<String> removed = ScannerConfigurationFiles.removeFrom(clone);

            assertThat(clone.resolve(".semgrepignore"))
                    .describedAs("the link itself is the tree's configuration, and goes")
                    .doesNotExist();
            assertThat(Files.exists(clone.resolve(".semgrepignore"), LinkOption.NOFOLLOW_LINKS)).isFalse();
            assertThat(kept).describedAs("what it pointed to is not the clone's to delete").exists();
            assertThat(keptToo).describedAs("a linked directory is never walked into").exists();
            assertThat(clone.resolve("linked")).describedAs("a link of another name is left alone").exists();
            assertThat(removed).containsExactly(".semgrepignore");
        }

        @Test
        @DisplayName("a directory bearing one of the names goes with what it holds, and the rest of the tree stays")
        void directoriesOfTheNameGo() throws IOException {
            Path clone = Files.createDirectories(root.resolve("clone"));
            Files.createDirectories(clone.resolve("a/.gitleaksignore/inner"));
            Files.writeString(clone.resolve("a/.gitleaksignore/inner/x"), "x");
            Files.writeString(clone.resolve("a/app.py"), "print(1)\n");
            Files.writeString(clone.resolve(".checkov.yml"), "skip-check: []\n");

            List<String> removed = ScannerConfigurationFiles.removeFrom(clone);

            assertThat(clone.resolve("a/.gitleaksignore")).doesNotExist();
            assertThat(clone.resolve(".checkov.yml")).doesNotExist();
            assertThat(clone.resolve("a/app.py")).exists();
            assertThat(removed).containsExactlyInAnyOrder(
                    "a" + clone.getFileSystem().getSeparator() + ".gitleaksignore", ".checkov.yml");
        }

        @Test
        @DisplayName("from a tree that carries none, nothing")
        void nothingToRemove() throws IOException {
            Path clone = Files.createDirectories(root.resolve("clone"));
            Files.writeString(clone.resolve("README.md"), "# readme\n");

            assertThat(ScannerConfigurationFiles.removeFrom(clone)).isEmpty();
            assertThat(clone.resolve("README.md")).exists();
        }
    }
}

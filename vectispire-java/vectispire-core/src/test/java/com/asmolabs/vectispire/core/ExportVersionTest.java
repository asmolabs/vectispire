package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The product's version, in the four places that state it.
 *
 * <h2>What went wrong</h2>
 *
 * <p>They disagreed. The signed jar was {@code 0.9.0}; the npm workspace said {@code 1.0.0}; the
 * exported documents announced {@code 1.0.0} through a configuration default; and two export
 * builders carried {@code 1.0.0} again as a hardcoded fallback. Nothing failed, because nothing
 * compared them.
 *
 * <p><b>The cost lands in the one file an assessor opens.</b> A VEX or CSAF document names the tool
 * that produced it, so a document claiming a version nobody can download cannot be reconciled with
 * the artefact somebody verified — and reconciling those two is the entire point of signing the
 * artefact.
 *
 * <h2>Why a test rather than one source</h2>
 *
 * <p>Gradle owns the build's version, Spring owns the runtime default, and the domain module owns a
 * fallback it must be able to state without reading either. Collapsing them into one source would
 * mean the domain reading a build file at runtime, which is worse than repeating a string. The
 * repetition is fine; the drift is not, and this is what catches it.
 */
@DisplayName("the version the product states about itself")
class ExportVersionTest {

    private static final Pattern GRADLE = Pattern.compile("^version=(.+)$", Pattern.MULTILINE);
    private static final Pattern YAML = Pattern.compile("tool-version: \\$\\{VECTISPIRE_VERSION:([^}]+)}");
    private static final Pattern JAVA = Pattern.compile("TOOL_VERSION = \"([^\"]+)\"");
    private static final Pattern NPM = Pattern.compile("\"version\": \"([^\"]+)\"");

    @Test
    @DisplayName("is the same in the build, the runtime default, the domain fallback and npm")
    void every_declaration_agrees() throws IOException {
        Path root = repositoryRoot();
        String built = first(GRADLE, root.resolve("vectispire-java/gradle.properties"));

        assertThat(first(YAML, root.resolve(
                        "vectispire-java/vectispire-core/src/main/resources/application.yaml")))
                .as("the runtime default an exported document carries")
                .isEqualTo(built);

        assertThat(first(JAVA, root.resolve("vectispire-java/vectispire-common/src/main/java/"
                        + "com/asmolabs/vectispire/common/domain/exports/ExportDefaults.java")))
                .as("the fallback the export builders use when nothing is configured")
                .isEqualTo(built);

        assertThat(first(NPM, root.resolve("package.json")))
                .as("the npm workspace root")
                .isEqualTo(built);
        assertThat(first(NPM, root.resolve("vectispire-angular/package.json")))
                .as("the front-end workspace")
                .isEqualTo(built);
    }

    private static String first(Pattern pattern, Path file) throws IOException {
        Matcher matcher = pattern.matcher(Files.readString(file, StandardCharsets.UTF_8));
        assertThat(matcher.find()).as("%s states a version", file.getFileName()).isTrue();
        return matcher.group(1).trim();
    }

    /** The directory holding both workspaces, found rather than counted to. */
    private static Path repositoryRoot() {
        Path directory = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (directory != null) {
            if (Files.isDirectory(directory.resolve("vectispire-angular"))
                    && Files.isDirectory(directory.resolve("vectispire-java"))) {
                return directory;
            }
            directory = directory.getParent();
        }
        throw new AssertionError("no directory above " + System.getProperty("user.dir")
                + " holds both workspaces");
    }
}

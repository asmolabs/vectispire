package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.services.shared.ProductVersion;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The version the product states about itself.
 *
 * <h2>What went wrong, twice</h2>
 *
 * <p>First the declarations disagreed: the signed jar was {@code 0.9.0}, the npm workspace
 * {@code 1.0.0}, the exported documents {@code 1.0.0} through a configuration default and two export
 * builders {@code 1.0.0} again as a hardcoded fallback. A test then compared the four literals —
 * which stopped the drift and kept the literals: every release meant editing Java, YAML and JSON to
 * restate one number, and the signed documents still read it from two different sources.
 *
 * <p>Now the build states it once. {@code ProductVersion} reads the build's own metadata, every
 * document takes its version from there, and nothing else in the backend repeats it. What is left
 * to check is that the running application really says what Gradle built — the wiring, which no
 * comparison of files can see — and that the npm workspaces, which have no build-info, agree.
 */
@DisplayName("the version the product states about itself")
class ExportVersionTest extends VectispireContextTest {

    private static final Pattern GRADLE = Pattern.compile("^version=(.+)$", Pattern.MULTILINE);
    private static final Pattern NPM = Pattern.compile("\"version\": \"([^\"]+)\"");
    private static final Pattern YAML_DEFAULT = Pattern.compile("tool-version: \\$\\{VECTISPIRE_VERSION:([^}]*)}");

    @Autowired
    private ProductVersion version;

    @Test
    @DisplayName("is the one Gradle built, as the running application states it")
    void theApplicationStatesTheBuiltVersion() throws IOException {
        assertThat(version.get()).isEqualTo(built());
    }

    @Test
    @DisplayName("is not repeated in the runtime configuration, whose default defers to the build")
    void theConfigurationDoesNotRestateIt() throws IOException {
        // A literal here is how SARIF and CSAF came to announce a version the build did not have.
        assertThat(first(YAML_DEFAULT, repositoryRoot().resolve(
                        "vectispire-java/vectispire-core/src/main/resources/application.yaml")))
                .isEmpty();
    }

    @Test
    @DisplayName("is the same in both npm workspaces, which have no build metadata to read")
    void theNpmWorkspacesAgree() throws IOException {
        Path root = repositoryRoot();
        assertThat(first(NPM, root.resolve("package.json"))).as("the npm workspace root").isEqualTo(built());
        assertThat(first(NPM, root.resolve("vectispire-angular/package.json")))
                .as("the front-end workspace")
                .isEqualTo(built());
    }

    private static String built() throws IOException {
        return first(GRADLE, repositoryRoot().resolve("vectispire-java/gradle.properties"));
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

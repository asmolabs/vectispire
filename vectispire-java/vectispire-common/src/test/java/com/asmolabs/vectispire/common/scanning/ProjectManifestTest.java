package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("what the scanned tree says about itself")
class ProjectManifestTest {

    @TempDir
    Path source;

    @Nested
    @DisplayName("Maven")
    class Maven {

        @Test
        @DisplayName("reads the project's own version, not a dependency's")
        void notADependencysVersion() throws IOException {
            // The trap this test exists for: every `<dependency>` carries a `<version>` too, and
            // the first one in document order is a plausible, wrong answer nobody would question
            // on a screen. Spring's version here is deliberately more recent-looking than the
            // project's, so a wrong reading is unmistakable.
            write("pom.xml", """
                    <project>
                      <artifactId>arm-libs-spring</artifactId>
                      <version>2.4.1</version>
                      <dependencies>
                        <dependency>
                          <groupId>org.springframework</groupId>
                          <artifactId>spring-core</artifactId>
                          <version>6.2.0</version>
                        </dependency>
                      </dependencies>
                    </project>
                    """);

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("maven", "2.4.1"));
        }

        @Test
        @DisplayName("falls back to the parent's version, which is where a Spring Boot module states it")
        void inheritedFromTheParent() throws IOException {
            write("pom.xml", """
                    <project>
                      <parent>
                        <groupId>be.civadis</groupId>
                        <artifactId>arm-parent</artifactId>
                        <version>1.8.0</version>
                      </parent>
                      <artifactId>arm-libs-spring</artifactId>
                    </project>
                    """);

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("maven", "1.8.0"));
        }

        @Test
        @DisplayName("reads no entity, because the XML comes from the audited repository")
        void doctypesAreRefused() throws IOException {
            // A pom carrying a doctype could read a file off the scanning host or open a
            // connection on its author's behalf. The parser refuses the doctype outright, so the
            // read fails — and a failed read still reports the ecosystem, which the filename
            // already established, with no version.
            Path secret = source.resolve("secret.txt");
            Files.writeString(secret, "the-agents-configuration");
            write("pom.xml", """
                    <?xml version="1.0"?>
                    <!DOCTYPE project [<!ENTITY stolen SYSTEM "file://%s">]>
                    <project><version>&stolen;</version></project>
                    """.formatted(secret.toAbsolutePath()));

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("maven", null));
        }
    }

    @Nested
    @DisplayName("the other ecosystems")
    class Others {

        @Test
        @DisplayName("Gradle states its version in gradle.properties, not in a script this would have to interpret")
        void gradleProperties() throws IOException {
            write("build.gradle.kts", "plugins { java }");
            write("gradle.properties", "version=3.0.0-SNAPSHOT\norg.gradle.caching=true\n");

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("gradle", "3.0.0-SNAPSHOT"));
        }

        @Test
        @DisplayName("a Gradle build with no properties file is still identified, with no version")
        void gradleWithoutAVersion() throws IOException {
            write("build.gradle", "apply plugin: 'java'");

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("gradle", null));
        }

        @Test
        @DisplayName("npm")
        void packageJson() throws IOException {
            write("package.json", "{\"name\":\"vectispire\",\"version\":\"0.1.0\"}");

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("npm", "0.1.0"));
        }

        @Test
        @DisplayName("Python takes the version from its own table, not from the first pin in the file")
        void pyprojectSection() throws IOException {
            // `version = "..."` appears under half the tables in a pyproject: pinned
            // dependencies, tool configuration. Matching the first one means matching whichever
            // table the author happened to put first.
            write("pyproject.toml", """
                    [build-system]
                    requires = ["setuptools"]

                    [tool.black]
                    version = "24.1.0"

                    [project]
                    name = "scan-api"
                    version = "2.2.0"
                    """);

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("python", "2.2.0"));
        }
    }

    @Nested
    @DisplayName("when there is nothing to read")
    class Nothing {

        @Test
        @DisplayName("a tree with no manifest is absent, not a failure")
        void noManifest() {
            // A documentation repository or a pile of scripts is a legitimate target. Reporting
            // this as a broken step would mark such a scan incomplete for ever.
            assertThat(ProjectManifest.read(source)).isEmpty();
        }

        @Test
        @DisplayName("the build file that produces the artifact wins over the frontend's package.json")
        void theBuildFileComesFirst() throws IOException {
            // A Spring project with a bundled frontend carries both. Reporting the frontend's
            // version as the project's is wrong in a way nobody notices.
            write("pom.xml", "<project><version>1.0.0</version></project>");
            write("package.json", "{\"version\":\"0.0.0-frontend\"}");

            assertThat(ProjectManifest.read(source))
                    .contains(new ProjectManifest.Project("maven", "1.0.0"));
        }
    }

    private void write(String name, String content) throws IOException {
        Files.writeString(source.resolve(name), content);
    }
}

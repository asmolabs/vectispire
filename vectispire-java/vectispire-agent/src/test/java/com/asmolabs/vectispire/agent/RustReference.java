package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The reference files the Rust agent's Kubernetes executor is held to, under {@code vectispire-rust/reference/} —
 * this module's copy of {@code vectispire-common}'s {@code ReferenceSet}, whose test classes this module cannot see.
 *
 * <p><b>Checked here too, not only written.</b> Without {@code -Dvectispire.rust.reference.write=true} a test fails
 * when its answers differ from the committed file, so a change to the executor's behaviour is red on this side until
 * the file is regenerated, and red on the Rust side until the port follows.
 */
public final class RustReference {

    private RustReference() {}

    /** Writes {@code content} in write mode, otherwise requires the committed file to say exactly it. */
    public static void expect(String relative, String content) {
        String dir = System.getProperty("vectispire.rust.reference");
        assertThat(dir).as("vectispire.rust.reference is set by vectispire-agent's test task").isNotBlank();
        Path file = Path.of(dir).resolve(relative);
        if (Boolean.getBoolean("vectispire.rust.reference.write")) {
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, content, StandardCharsets.UTF_8);
            } catch (IOException unwritable) {
                throw new UncheckedIOException(unwritable);
            }
            return;
        }
        assertThat(file)
                .as("%s differs from what the Java side answers. Regenerate with ./gradlew :vectispire-agent:test "
                        + "--tests '*ReferenceSetTest*' -Dvectispire.rust.reference.write=true, then make the Rust "
                        + "port agree (vectispire-rust/check.sh).", relative)
                .exists()
                .content(StandardCharsets.UTF_8)
                .isEqualTo(content);
    }
}

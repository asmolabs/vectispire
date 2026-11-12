package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The files the Rust control plane's crates are held to, written by this module's tests — what {@code
 * vectispire-common}'s {@code ReferenceSet} is to the agent's port, for the answers only {@code core} can give: the
 * module model Spring Modulith reads, the maintenance tick's composition.
 *
 * <p><b>Checked on every build, not only written.</b> Without {@code -Dvectispire.rust.reference.write=true} the
 * caller fails when its answer differs from the committed file, so a change on this side is red here until the file
 * is regenerated, and red on the Rust side until the port follows.
 */
public final class RustReference {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private RustReference() {}

    public static ObjectNode object() {
        return JSON.createObjectNode();
    }

    /**
     * Writes {@code content} in write mode, otherwise requires the committed file to say exactly it.
     *
     * @param test the class to rerun, named in the failure so that the regeneration command can be copied
     */
    public static void expect(String relative, ObjectNode content, Class<?> test) {
        String dir = System.getProperty("vectispire.rust.reference");
        assertThat(dir).as("vectispire.rust.reference is set by vectispire-core's test task").isNotBlank();
        Path file = Path.of(dir).resolve(relative);
        String text;
        try {
            text = JSON.writeValueAsString(content) + "\n";
        } catch (IOException unwritable) {
            throw new UncheckedIOException(unwritable);
        }
        if (Boolean.getBoolean("vectispire.rust.reference.write")) {
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, text, StandardCharsets.UTF_8);
            } catch (IOException unwritable) {
                throw new UncheckedIOException(unwritable);
            }
            return;
        }
        assertThat(file)
                .as("%s differs from what the Java side answers. Regenerate with ./gradlew :vectispire-core:test --tests "
                        + "'*%s*' -Dvectispire.rust.reference.write=true, then make the Rust port agree "
                        + "(vectispire-rust/check.sh).", relative, test.getSimpleName())
                .exists()
                .content(StandardCharsets.UTF_8)
                .isEqualTo(text);
    }
}

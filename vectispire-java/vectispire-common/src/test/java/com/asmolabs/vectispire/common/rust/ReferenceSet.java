package com.asmolabs.vectispire.common.rust;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The files the Rust agent's port is held to: what this code answers for a fixed set of inputs.
 *
 * <p><b>Two implementations of one behaviour agree only where something compares them.</b> The Rust
 * agent (`vectispire-rust/`) reimplements what the agent does with this module's classes — the
 * parsers whose findings enter an issue's fingerprint, the URL checks, the crypto — and a difference
 * there is not a style question: a path normalised differently resolves every issue and recreates it,
 * losing its triage. So each reference test writes this side's answers under
 * {@code vectispire-rust/reference/}, and the Rust tests read them.
 *
 * <p><b>Checked here too, not only written.</b> Without {@code -Dvectispire.rust.reference.write=true}
 * a test fails when its answers differ from the committed file: a change to the Java behaviour is then
 * red on this side until the file is regenerated, and red on the Rust side until the port follows —
 * which is what makes the reference set a merge blocker rather than a snapshot nobody reads.
 */
public final class ReferenceSet {

    private ReferenceSet() {}

    /** The reference directory, named by the build. */
    public static Path root() {
        String dir = System.getProperty("vectispire.rust.reference");
        assertThat(dir).as("vectispire.rust.reference is set by vectispire-common's test task").isNotBlank();
        return Path.of(dir);
    }

    public static Path resolve(String relative) {
        return root().resolve(relative);
    }

    public static String read(String relative) {
        try {
            return Files.readString(resolve(relative), StandardCharsets.UTF_8);
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    /** Writes {@code content} in write mode, otherwise requires the committed file to say exactly it. */
    public static void expect(String relative, String content) {
        Path file = resolve(relative);
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
                .as("%s differs from what the Java side answers. Regenerate with ./gradlew :vectispire-common:test "
                        + "--tests '*ReferenceSetTest*' -Dvectispire.rust.reference.write=true, then make the Rust "
                        + "port agree (vectispire-rust/check.sh).", relative)
                .exists()
                .content(StandardCharsets.UTF_8)
                .isEqualTo(content);
    }
}

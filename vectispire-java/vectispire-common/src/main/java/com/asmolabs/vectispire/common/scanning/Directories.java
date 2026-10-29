package com.asmolabs.vectispire.common.scanning;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/** Removing the directories a scan, a fetch or a database download leaves behind. */
public final class Directories {

    private Directories() {}

    /**
     * Deletes a directory and everything under it, as far as it can, and never throws.
     *
     * <p><b>Best effort, on purpose.</b> One undeletable file must not keep the rest — a cloned tree
     * is often large, and a scan's workspace holds the secrets report in the clear. And an absent
     * directory, or one that cannot be walked, is not an error: every caller deletes in a {@code
     * finally} or after a failure, where throwing would replace the exception that explains what went
     * wrong with "could not delete a temporary directory".
     */
    public static void deleteRecursively(Path root) {
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // One undeletable file must not stop the rest from going.
                }
            });
        } catch (IOException ignored) {
            // Absent is the outcome wanted.
        }
    }
}

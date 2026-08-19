package com.asmolabs.zanshin.common.scanning;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.function.Function;

/**
 * A scan's workspace: an ephemeral directory, and its layout.
 *
 * <p><b>The scanned tree is a subdirectory, not the root.</b> Anything Zanshin produces itself
 * — the SBOM for the vulnerability matcher, the secrets report — lands at the root, hence
 * deliberately <em>outside</em> the analysed tree.
 *
 * <p>The separation is structural rather than a list of files to ignore, because two of those
 * artifacts are actively harmful to feed back in: the secrets report contains <b>every
 * detected secret in the clear</b>, and a Syft SBOM alone exceeds a model review's budget.
 * Keeping the target in its own directory means nothing walking the source tree can reach
 * them, whatever gets added later.
 *
 * <p><b>Rules are copied into the workspace</b> rather than read where they live. It looks
 * like a detour — they already exist beside this code — but it is the only location that works
 * everywhere: volume paths are resolved by the Docker <em>daemon</em>, not by the process
 * calling it. When Zanshin itself runs in a container with the socket mounted, a directory
 * from its own image is invisible to the sibling container. The workspace is the one path both
 * sides see.
 */
public record Workspace(Path root, Path source, Path rules) {

    /** The subdirectory holding <b>only</b> the scan's target. */
    public static final String SOURCE_SUBDIR = "source";

    /** Its sibling, carrying the rule tree for the duration of the scan. */
    public static final String RULES_SUBDIR = "rules";

    /**
     * Creates a workspace, hands it to {@code body}, and guarantees its removal.
     *
     * <p>Removal is in a {@code finally} and not after the call: a scan that fails leaves
     * behind a cloned tree, sometimes a large one, and often the secrets report listing what it
     * found. Failures are exactly the case where cleanup gets forgotten, and the only one where
     * it really matters.
     */
    public static <T> T withWorkspace(Function<Workspace, T> body) {
        Path root;
        try {
            // A random suffix rather than a constructed name: a second scan of the same target
            // must not overwrite the first, and the directory is created 0700.
            root = Files.createTempDirectory("zanshin-scan-");
        } catch (IOException e) {
            throw new UncheckedIOException("could not create a scan workspace", e);
        }

        Workspace workspace = new Workspace(root, root.resolve(SOURCE_SUBDIR), root.resolve(RULES_SUBDIR));
        try {
            return body.apply(workspace);
        } finally {
            deleteRecursively(root);
        }
    }

    private static void deleteRecursively(Path root) {
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // One undeletable file must not stop the rest from going.
                }
            });
        } catch (IOException ignored) {
            // An absent directory is not an error, and throwing here would mask the original
            // exception — the one that explains why the scan failed.
        }
    }
}

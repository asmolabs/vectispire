package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.scanning.Workspace;

/**
 * Paths as the scanner containers see them.
 *
 * <p><b>Built as POSIX strings, never with the host's path separator.</b> The target is a path
 * <em>inside</em> a container, which is Linux whatever machine launched the scan. Composing it
 * with {@code Path} would produce backslashes on Windows and a container that finds nothing.
 */
final class ContainerPaths {

    /** Where the workspace root is mounted in every scanner container. */
    static final String MOUNT = "/repo";

    /**
     * The only writable, disk-backed path a scanner container gets.
     *
     * <p>The root filesystem is read-only and the scratch space is a tmpfs, so anything that
     * has to survive in size — the vulnerability database, at roughly 1.9 GB — needs a real
     * mount. Only the matcher asks for one. Taken from {@code ContainerRunner} rather than
     * repeated, because the runner exports the environment variable that names it.
     */
    static final String DATABASE_CACHE = com.asmolabs.vectispire.common.scanning.ContainerRunner.DATABASE_CACHE_MOUNT;

    private ContainerPaths() {}

    /** The scanned tree, or a subdirectory of it. */
    static String source(String subPath) {
        String base = MOUNT + "/" + Workspace.SOURCE_SUBDIR;
        return subPath == null || subPath.isBlank() ? base : base + "/" + trim(subPath);
    }

    /** A file in the rule tree Vectispire copied into the workspace. */
    static String rules(String... segments) {
        return MOUNT + "/" + Workspace.RULES_SUBDIR + "/" + String.join("/", segments);
    }

    /** Turns a container path back into one relative to the scanned tree. */
    static String relativeToSource(String containerPath, String subPath) {
        if (containerPath == null) {
            return "";
        }
        String prefix = source(subPath);
        String relative = containerPath.startsWith(prefix) ? containerPath.substring(prefix.length()) : containerPath;
        return relative.replaceAll("^/+", "");
    }

    private static String trim(String value) {
        return value.replaceAll("^/+", "").replaceAll("/+$", "");
    }
}

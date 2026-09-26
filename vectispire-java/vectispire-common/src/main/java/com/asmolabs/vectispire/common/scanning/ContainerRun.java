package com.asmolabs.vectispire.common.scanning;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * What to run, and everything it is allowed to reach.
 *
 * <p>The defaults are the closed ones. Every field that widens what a scanner can do has to be
 * set deliberately, which is the point: a new scanner added six months from now inherits the
 * restrictive shape unless its author argues otherwise.
 *
 * @param network <b>cut off unless the tool genuinely has somewhere to look.</b> The
 *     vulnerability matcher needs its database and the cataloguer needs the registry; the
 *     secrets scanner, the IaC checker and a directory SBOM never do
 * @param asRoot needed by recent images that run as an unprivileged user: the workspace is a
 *     0700 temp directory owned by Vectispire's user, which a non-root process cannot read.
 *     {@code cap_drop: ALL} and {@code no-new-privileges} still apply
 * @param user {@code uid:gid} to run as, or {@code null} for the image's own user (or root, with
 *     {@link #asRoot}). Set for a tool that <em>writes</em> into a mount: what root writes there is
 *     root's on the host, and Vectispire, unprivileged, cannot delete it afterwards
 */
public record ContainerRun(
        String image,
        List<String> command,
        List<Mount> mounts,
        String label,
        boolean network,
        boolean asRoot,
        Duration timeout,
        String user) {

    /** @param readOnly explicit, and true wherever it can be */
    public record Mount(String source, String target, boolean readOnly) {

        public static Mount readOnly(String source, String target) {
            return new Mount(source, target, true);
        }

        public static Mount writable(String source, String target) {
            return new Mount(source, target, false);
        }

        String toBind() {
            return source + ":" + target + (readOnly ? ":ro" : "");
        }
    }

    /** The closed shape: no network, not root, default timeout. */
    public static ContainerRun of(String image, List<String> command, List<Mount> mounts, String label) {
        return new ContainerRun(image, List.copyOf(command), List.copyOf(mounts), label, false, false, null, null);
    }

    public ContainerRun withNetwork() {
        return new ContainerRun(image, command, mounts, label, true, asRoot, timeout, user);
    }

    /** Named `runningAsRoot` rather than `asRoot`: the latter is the component's accessor. */
    public ContainerRun runningAsRoot() {
        return new ContainerRun(image, command, mounts, label, network, true, timeout, user);
    }

    /**
     * Runs as {@code uid:gid} — the owner of the directory the tool writes into, so that what it
     * writes stays deletable by the process that created the directory.
     */
    public ContainerRun runningAs(String uidGid) {
        return new ContainerRun(image, command, mounts, label, network, false, timeout, uidGid);
    }

    public ContainerRun withTimeout(Duration value) {
        return new ContainerRun(image, command, mounts, label, network, asRoot, value, user);
    }

    /**
     * {@code uid:gid} of a directory, for a tool that writes into it — empty when the file system
     * reports no owner, and the caller then keeps whatever it did before.
     */
    public static Optional<String> ownerOf(Path directory) {
        try {
            Object uid = Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS);
            Object gid = Files.getAttribute(directory, "unix:gid", LinkOption.NOFOLLOW_LINKS);
            return Optional.of(uid + ":" + gid);
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException unreported) {
            return Optional.empty();
        }
    }

    List<String> binds() {
        return mounts.stream().map(Mount::toBind).toList();
    }
}

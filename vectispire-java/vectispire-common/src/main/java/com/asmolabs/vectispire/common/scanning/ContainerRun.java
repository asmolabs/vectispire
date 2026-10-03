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
 * @param asRoot root inside the container, with {@code cap_drop: ALL} and {@code no-new-privileges}
 *     still applied — which means <b>without</b> {@code CAP_DAC_OVERRIDE}: such a root reads only what
 *     the permission bits let it, and the workspace is a 0700 directory owned by Vectispire's user.
 *     Kept as the fallback of {@link #runningAsOwnerOf} for a file system that reports no owner
 * @param user {@code uid:gid} to run as, or {@code null} for the image's own user (or root, with
 *     {@link #asRoot}). Set for a tool that <em>writes</em> into a mount: what root writes there is
 *     root's on the host, and Vectispire, unprivileged, cannot delete it afterwards
 * @param output a writable directory with a ceiling, or {@code null} — see {@link BoundedOutput}
 * @param login the pull credentials handed to the tool for one registry, or {@code null} — see
 *     {@link RegistryLogin}
 */
public record ContainerRun(
        String image,
        List<String> command,
        List<Mount> mounts,
        String label,
        boolean network,
        boolean asRoot,
        Duration timeout,
        String user,
        BoundedOutput output,
        RegistryLogin login) {

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

    /**
     * A directory the tool may write into, which <b>cannot hold more than {@code bytes}</b>.
     *
     * <p><b>A bind mount carries no size.</b> The plugins' output used to be a directory of the
     * workspace bound writable into the container, and a plugin — code somebody else wrote — could
     * fill the executor's disk through it for as long as its timeout allowed: the report was read up
     * to the ceiling, but nothing bounded what was written beside it.
     *
     * <p>A size-limited tmpfs is the bound the kernel enforces, and the obvious one does not work:
     * {@code HostConfig.Tmpfs} lives in the container's own mount namespace, which the archive API
     * cannot read — not while the container runs, not after (measured on Docker 29: "Could not find
     * the file"). What it can read is a <em>volume</em>, mounted on the daemon's side. So the
     * directory is an anonymous volume of the local driver, of type tmpfs with {@code size=} and
     * {@code nr_inodes=}, declared inside {@code POST /containers/create} — the socket proxy's
     * {@code VOLUMES: 0} stays as it is, since no {@code /volumes} call is made. A tmpfs volume is
     * unmounted, and emptied, when the last container using it stops; so a <b>holder</b> — a pinned
     * busybox that only sleeps, in the same closed shape — owns it and keeps it mounted, the tool
     * reaches it through {@code VolumesFrom}, and the file is read from the holder once the tool has
     * exited. Both are removed in a {@code finally}, the volume with them.
     *
     * <p>Memory, not disk: the pages are charged to the tool's own memory ceiling, and the host's
     * disk is not touched at all.
     *
     * @param target where the directory appears in the container
     * @param bytes what it may hold, everything in it counted
     * @param holderImage the image that keeps the directory alive, pinned by digest like any other
     * @param file the one file read back — a bare name in {@code target}
     */
    public record BoundedOutput(String target, long bytes, String holderImage, String file) {

        public BoundedOutput {
            if (bytes <= 0) {
                throw new IllegalArgumentException("A bounded output holds a positive number of bytes.");
            }
            if (file == null || file.isEmpty() || file.contains("/") || file.startsWith(".")) {
                throw new IllegalArgumentException("The file read back is a bare name in the output directory.");
            }
        }
    }

    /**
     * The credentials this executor's pulls use for {@code reference}'s registry, handed to the tool
     * as a Docker configuration for the length of the run — and nothing when it holds none.
     *
     * <p><b>Named, never carried.</b> The request names the image; the runner resolves the credentials
     * from the Docker configuration its own pulls read, by the rule its pulls apply, writes them into
     * {@code directory} readable by their owner alone, mounts that read-only and erases it in the same
     * {@code finally} that removes the container. No caller holds them, so none can log them, put them
     * in a message, or keep them past the run.
     *
     * @param directory where the file is written for the run — a directory of the workspace no tool
     *     reads, on the daemon's host like every other mount
     */
    public record RegistryLogin(String reference, Path directory) {}

    /** The closed shape: no network, not root, default timeout. */
    public static ContainerRun of(String image, List<String> command, List<Mount> mounts, String label) {
        return new ContainerRun(image, List.copyOf(command), List.copyOf(mounts), label, false, false, null, null, null, null);
    }

    public ContainerRun withNetwork() {
        return new ContainerRun(image, command, mounts, label, true, asRoot, timeout, user, output, login);
    }

    /** Named `runningAsRoot` rather than `asRoot`: the latter is the component's accessor. */
    public ContainerRun runningAsRoot() {
        return new ContainerRun(image, command, mounts, label, network, true, timeout, user, output, login);
    }

    /**
     * Writes into a directory that cannot hold more than its ceiling, read back by the runner —
     * see {@link BoundedOutput}. Needs {@link #runningAs}: the directory belongs to that user.
     */
    public ContainerRun withBoundedOutput(BoundedOutput value) {
        return new ContainerRun(image, command, mounts, label, network, asRoot, timeout, user, value, login);
    }

    /**
     * Runs as {@code uid:gid} — the owner of the directory the tool writes into, so that what it
     * writes stays deletable by the process that created the directory.
     */
    public ContainerRun runningAs(String uidGid) {
        return new ContainerRun(image, command, mounts, label, network, false, timeout, uidGid, output, login);
    }

    /**
     * Runs as the owner of {@code directory} — the workspace, as a rule — and as root only where the
     * file system reports no owner.
     *
     * <p><b>Not root, because root cannot read it.</b> Every scanner but the matcher used to run as
     * root on the belief that root reads any directory; with every capability dropped it has no
     * {@code CAP_DAC_OVERRIDE}, and the 0700 workspace of an unprivileged Vectispire refused it
     * ("stat /repo/source: permission denied", "open /repo/rules/gitleaks/gitleaks.toml: permission
     * denied") — measured on 2026-09-27 in the shipped composition, once its workspaces reached the
     * daemon at all. Docker Desktop's file sharing grants that access where a Linux daemon does not,
     * which is how it went unseen. The owner reads what it cloned and can delete what it wrote.
     */
    public ContainerRun runningAsOwnerOf(Path directory) {
        return ownerOf(directory).map(this::runningAs).orElseGet(this::runningAsRoot);
    }

    /** Hands the tool the pull credentials for {@code reference}'s registry — see {@link RegistryLogin}. */
    public ContainerRun withRegistryLoginFor(String reference, Path directory) {
        return new ContainerRun(image, command, mounts, label, network, asRoot, timeout, user, output,
                new RegistryLogin(reference, directory));
    }

    public ContainerRun withTimeout(Duration value) {
        return new ContainerRun(image, command, mounts, label, network, asRoot, value, user, output, login);
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

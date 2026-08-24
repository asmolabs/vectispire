package com.asmolabs.vectispire.common.scanning;

import java.time.Duration;
import java.util.List;

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
 */
public record ContainerRun(
        String image,
        List<String> command,
        List<Mount> mounts,
        String label,
        boolean network,
        boolean asRoot,
        Duration timeout) {

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
        return new ContainerRun(image, List.copyOf(command), List.copyOf(mounts), label, false, false, null);
    }

    public ContainerRun withNetwork() {
        return new ContainerRun(image, command, mounts, label, true, asRoot, timeout);
    }

    /** Named `runningAsRoot` rather than `asRoot`: the latter is the component's accessor. */
    public ContainerRun runningAsRoot() {
        return new ContainerRun(image, command, mounts, label, network, true, timeout);
    }

    public ContainerRun withTimeout(Duration value) {
        return new ContainerRun(image, command, mounts, label, network, asRoot, value);
    }

    List<String> binds() {
        return mounts.stream().map(Mount::toBind).toList();
    }
}

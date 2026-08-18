package com.asmolabs.zanshin.common.scanning;

import com.asmolabs.zanshin.common.domain.targets.ImageReference;
import java.util.Optional;
import java.util.Set;

/**
 * What a scan has to do. Decided by the control plane, executed by the runner.
 *
 * <p><b>A target is a repository or an image, never both.</b> The original carried an optional
 * image reference beside a URL and switched on whichever was set — with a comment saying they
 * are mutually exclusive. A sealed interface says it instead, and the switch that dispatches on
 * it has to handle both cases or fail to compile.
 */
public record ScanTask(Target target, String rulesHash, Set<Step> steps) {

    /** What a scan can run. Each is optional: an operator may want only some of them. */
    public enum Step {
        DEPENDENCIES,
        SECRETS,
        IAC,
        SAST
    }

    public sealed interface Target {

        /**
         * @param privateKey the decrypted key, or {@code null} for a public repository
         */
        record Repository(String url, String branch, String subPath, String privateKey) implements Target {}

        /**
         * @param platform the variant to pull. The image scanned must be the one that runs: the
         *     daemon otherwise returns the host's architecture, and an arm64 development machine
         *     would audit a variant nobody deploys
         */
        record Image(ImageReference reference, String platform) implements Target {}
    }

    /**
     * @param rulesHash the uploaded rule set that must be used, or {@code null} for the bundled
     *     rules and the operator's directory alone.
     *     <p>Carried by the task rather than read by the executor, and that is what makes every
     *     executor identical. An agent reading "the active set" for itself would scan with
     *     whatever it found at the moment it asked, and two agents could diverge — resolving
     *     and recreating the SAST backlog as they take turns.
     */
    public ScanTask {
        steps = steps == null ? Set.of() : Set.copyOf(steps);
    }

    public boolean runs(Step step) {
        return steps.contains(step);
    }

    public Optional<String> subPath() {
        return target instanceof Target.Repository repository
                ? Optional.ofNullable(repository.subPath())
                : Optional.empty();
    }
}

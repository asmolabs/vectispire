package com.asmolabs.vectispire.common.scanning;

import java.time.Duration;

/**
 * What a scanner container may consume before it is killed.
 *
 * <p><b>These containers analyse hostile input by definition</b> — the metadata of an image
 * nobody controls, a repository written by somebody else. The limits remove the cheap
 * escalations: no new privileges, no capabilities, a memory ceiling instead of an out-of-memory
 * kill on the host, a process ceiling instead of a fork bomb, and a share of the CPU instead of
 * all of it.
 *
 * <p>A record rather than constants read from the environment at class load, for the reason
 * that keeps recurring in this port: values fixed at initialization cannot be varied by a test,
 * and a memory ceiling no test can lower is a ceiling nobody has ever seen enforced.
 *
 * @param memory a container that exceeds this dies; the host does not
 * @param pids what turns a fork bomb into a dead container
 * @param cpus how many cores a scanner may use, in nano-CPU units as the daemon counts them
 */
public record ScannerLimits(long memory, long pids, Duration timeout, long nanoCpus) {

    /** One CPU, in the units {@code HostConfig.withNanoCPUs} expects. */
    private static final long ONE_CPU = 1_000_000_000L;

    public static final ScannerLimits DEFAULT = new ScannerLimits(
            2048L * 1024 * 1024, 512, Duration.ofMinutes(15), defaultCpus());

    /**
     * Every core but one.
     *
     * <p><b>The gap this closes was documented as closed for weeks.</b> The dimensioning view
     * listed a quota of "2.0 vCPUs" per scanner container; no code applied any CPU limit at all,
     * so an operator sizing a host against that figure was sizing against nothing.
     *
     * <p><b>Why "all but one" rather than a fixed number.</b> The harm is not that a scanner works
     * hard — semgrep and grype are CPU-bound and a cap that starves them turns a five-minute scan
     * into a timeout, which is a denial of service delivered by the defence. The harm is that a
     * repository nobody controls can take the <em>last</em> core and leave the control plane
     * unable to answer a gate call for the fifteen minutes its timeout allows. Leaving one core is
     * what separates those two, and it scales with the host instead of being wrong on both a
     * two-core VM and a sixty-four-core builder.
     *
     * <p>Floored at one, because {@code availableProcessors() - 1} is zero on a single-core host
     * and a quota of zero means "no limit" to the daemon — the one value that would silently
     * restore the behaviour this exists to remove.
     */
    private static long defaultCpus() {
        return Math.max(1, Runtime.getRuntime().availableProcessors() - 1) * ONE_CPU;
    }
}

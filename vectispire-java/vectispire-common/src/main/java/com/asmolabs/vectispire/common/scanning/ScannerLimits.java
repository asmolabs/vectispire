package com.asmolabs.vectispire.common.scanning;

import java.time.Duration;

/**
 * What a scanner container may consume before it is killed.
 *
 * <p><b>These containers analyse hostile input by definition</b> — the metadata of an image
 * nobody controls, a repository written by somebody else. The limits remove the cheap
 * escalations: no new privileges, no capabilities, a memory ceiling instead of an out-of-memory
 * kill on the host, a process ceiling instead of a fork bomb.
 *
 * <p>A record rather than constants read from the environment at class load, for the reason
 * that keeps recurring in this port: values fixed at initialization cannot be varied by a test,
 * and a memory ceiling no test can lower is a ceiling nobody has ever seen enforced.
 *
 * @param memory a container that exceeds this dies; the host does not
 * @param pids what turns a fork bomb into a dead container
 */
public record ScannerLimits(long memory, long pids, Duration timeout) {

    public static final ScannerLimits DEFAULT = new ScannerLimits(2048L * 1024 * 1024, 512, Duration.ofMinutes(15));
}

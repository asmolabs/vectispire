package com.asmolabs.vectispire.core.services;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param enabled switchable off for the deployment whose control plane does not scan. Read on
 *     every turn rather than at startup, so it can be stopped without a restart
 * @param maxConcurrent how many scans this host runs at once
 * @param labels this host's capabilities, comma-separated. <b>Empty by default, so it only
 *     takes work with no requirement.</b> The opposite — "the built-in worker matches
 *     everything" — would make targeting useless on any single-instance install, which is most
 *     of them
 */
@ConfigurationProperties("vectispire.worker")
public record WorkerProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("2") int maxConcurrent,
        @DefaultValue("") String labels) {

    public WorkerProperties {
        maxConcurrent = maxConcurrent > 0 ? maxConcurrent : 2;
    }
}

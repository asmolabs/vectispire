package com.asmolabs.vectispire.core.scanning;

import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * @param enabled switchable off for the deployment whose control plane does not scan. Read on
 *     every turn rather than at startup, so it can be stopped without a restart
 * @param maxConcurrent how many scans this host runs at once, one at least. <b>Refused at start
 *     below that, no longer read as 2</b>: zero or a negative count is a typing mistake — the switch
 *     for a host that does not scan is {@code enabled} — and replacing it in silence ran two scans on
 *     a host whose operator had asked for something else and was never told
 * @param labels this host's capabilities, comma-separated. <b>Empty by default, so it only
 *     takes work with no requirement.</b> The opposite — "the built-in worker matches
 *     everything" — would make targeting useless on any single-instance install, which is most
 *     of them
 */
@Validated
@ConfigurationProperties("vectispire.worker")
public record WorkerProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("2")
                @Positive(message = "must be at least 1; to stop the built-in worker, set VECTISPIRE_EMBEDDED_WORKER=false "
                        + "(vectispire.worker.enabled)")
                int maxConcurrent,
        @DefaultValue("") String labels) {}

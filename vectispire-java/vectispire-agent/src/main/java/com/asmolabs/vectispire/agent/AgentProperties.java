package com.asmolabs.vectispire.agent;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Everything the agent needs to know, and nothing more.
 *
 * @param url the control plane's address. A fixed configuration value, which is why redirects
 *     are refused: it has no reason to redirect, and following one would send a scan's results
 *     — or the claim that carries the API key — to a host nobody declared
 * @param token the API key shown once when the agent was created
 * @param claimWait how long the server is asked to hold a claim open. The long wait is the server's
 *     to bear, so a queued scan leaves within the second rather than at the next poll
 * @param heartbeat the interval between two signs of life during a scan. <b>Periodic, not tied
 *     to the scanner's steps</b>: a beat sent per step would go silent for the fifteen minutes
 *     Semgrep can take on a large repository, and the lease would lapse while it progresses
 */
@ConfigurationProperties("vectispire.agent")
public record AgentProperties(
        String url,
        String token,
        @DefaultValue("30s") Duration claimWait,
        @DefaultValue("10s") Duration retryDelay,
        @DefaultValue("60s") Duration heartbeat,
        @DefaultValue("docker") String scannerEngine,
        @DefaultValue("1") String version) {

    public AgentProperties {
        url = url == null ? "" : url.trim().replaceAll("/+$", "");
        token = token == null ? "" : token.trim();
        claimWait = clamp(claimWait, Duration.ofSeconds(1), Duration.ofMinutes(5));
        retryDelay = clamp(retryDelay, Duration.ofSeconds(1), Duration.ofMinutes(5));
        heartbeat = clamp(heartbeat, Duration.ofSeconds(5), Duration.ofMinutes(10));
    }

    private static Duration clamp(Duration value, Duration min, Duration max) {
        if (value == null || value.compareTo(min) < 0) {
            return min;
        }
        return value.compareTo(max) > 0 ? max : value;
    }
}

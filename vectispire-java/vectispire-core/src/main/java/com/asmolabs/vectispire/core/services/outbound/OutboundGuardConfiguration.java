package com.asmolabs.vectispire.core.services.outbound;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The guard every outbound URL passes.
 *
 * <p>A bean rather than a {@code new} at each call site, so a deployment that needs a different
 * resolver — a test, a machine with no DNS — replaces one thing and not seven. In this layer and
 * not in {@code config}, because it asks the scanning layer where the daemon is.
 */
@Configuration(proxyBeanMethods = false)
public class OutboundGuardConfiguration {

    /**
     * The daemon the embedded worker talks to, and the database: both on the internal network an
     * internal-only URL is allowed to reach, and neither ever a destination. A Unix socket or a
     * file database yields nothing, having no address to send to.
     */
    @Bean
    public OutboundUrlGuard outboundUrlGuard(@Value("${spring.datasource.url:}") String datasourceUrl) {
        List<OutboundUrlGuard.ReservedEndpoint> reserved = new ArrayList<>();
        // Null when no daemon is found — a control plane with the worker off and no socket, which is
        // how the CI smoke test starts it, and how it failed to start: the image stopped on a
        // NullPointerException here, which no unit test saw because every test machine has Docker.
        String docker = Objects.requireNonNullElse(ContainerRunner.resolveDockerHost(), "");
        OutboundUrlGuard.ReservedEndpoint.of(docker, docker.startsWith("https") ? 2376 : 2375, "the Docker daemon")
                .ifPresent(reserved::add);
        OutboundUrlGuard.ReservedEndpoint.of(
                        datasourceUrl, datasourceUrl.contains(":postgresql:") ? 5432 : 3306, "the database")
                .ifPresent(reserved::add);
        return new OutboundUrlGuard(reserved);
    }

    /**
     * The hosts repositories may be cloned from — every host when empty, the default. See
     * {@link GitHostAllowlist} for why it is opt-in, and why it is checked twice.
     */
    @Bean
    public GitHostAllowlist gitHostAllowlist(@Value("${vectispire.git.allowed-hosts:}") String allowedHosts) {
        return GitHostAllowlist.parse(allowedHosts);
    }
}

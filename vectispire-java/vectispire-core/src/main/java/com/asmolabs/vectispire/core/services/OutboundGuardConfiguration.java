package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import java.util.ArrayList;
import java.util.List;
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
        String docker = ContainerRunner.resolveDockerHost();
        OutboundUrlGuard.ReservedEndpoint.of(docker, docker.startsWith("https") ? 2376 : 2375, "the Docker daemon")
                .ifPresent(reserved::add);
        OutboundUrlGuard.ReservedEndpoint.of(
                        datasourceUrl, datasourceUrl.contains(":postgresql:") ? 5432 : 3306, "the database")
                .ifPresent(reserved::add);
        return new OutboundUrlGuard(reserved);
    }
}

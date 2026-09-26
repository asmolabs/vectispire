package com.asmolabs.vectispire.core.outbound.internal;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.ReservedEndpoints;
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
        // Null when no daemon is found — a control plane with the worker off and no socket, which is
        // how the CI smoke test starts it, and how it failed to start: the image stopped on a
        // NullPointerException here, which no unit test saw because every test machine has Docker.
        return guard(Objects.requireNonNullElse(ContainerRunner.resolveDockerHost(), ""), datasourceUrl);
    }

    /**
     * The guard for this daemon and this database — or no application at all.
     *
     * <p>An address {@link ReservedEndpoints} cannot read throws, and the context does not start. It
     * used to yield no reservation, in silence, and the guard then let a webhook reach the daemon or
     * the database of every deployment whose address {@code java.net.URI} happened not to parse.
     */
    public static OutboundUrlGuard guard(String dockerHost, String datasourceUrl) {
        List<OutboundUrlGuard.ReservedEndpoint> reserved = new ArrayList<>();
        reserved.addAll(ReservedEndpoints.ofDockerHost(dockerHost));
        reserved.addAll(ReservedEndpoints.ofDatasource(datasourceUrl));
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

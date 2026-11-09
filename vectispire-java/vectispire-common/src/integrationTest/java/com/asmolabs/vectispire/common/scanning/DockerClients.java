package com.asmolabs.vectispire.common.scanning;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;

/**
 * A client of the daemon for the suite's own bookkeeping — listing what a run left behind, starting
 * the socket proxy — which the runner deliberately cannot do.
 */
final class DockerClients {

    private DockerClients() {}

    /** The daemon {@link ContainerRunner} finds by itself. */
    static DockerClient local() {
        return at(ContainerRunner.resolveDockerHost());
    }

    static DockerClient at(String host) {
        DefaultDockerClientConfig.Builder builder = DefaultDockerClientConfig.createDefaultConfigBuilder();
        if (host != null && !host.isBlank()) {
            builder.withDockerHost(host);
        }
        DefaultDockerClientConfig config = builder.build();
        return DockerClientImpl.getInstance(config,
                new ApacheDockerHttpClient.Builder().dockerHost(config.getDockerHost()).build());
    }
}

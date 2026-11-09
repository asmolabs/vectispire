package com.asmolabs.vectispire.common.scanning;

import com.github.dockerjava.transport.DockerHttpClient;
import java.io.IOException;

/**
 * Every request to the daemon on a connection of its own.
 *
 * <p><b>Because the socket proxy closes an idle connection after ten seconds, and the client never
 * notices.</b> docker-java's pool keeps its connections for reuse and, by its own choice, never
 * checks one before handing it out; the proxy the composition ships (HAProxy, {@code timeout
 * http-keep-alive 10s}) closes each one ten seconds after its last response. The first request after
 * a pause then went out on a socket already closed — "docker-proxy:2375 failed to respond", or
 * "Broken pipe" — and a request that changes something ({@code POST /images/create}, {@code POST
 * /containers/create}) is not retried: two image scans out of three queued after a quiet minute
 * failed their only step, measured on 2026-09-27 in the shipped composition. A direct daemon keeps
 * its connections open, which is why no suite saw it.
 *
 * <p>{@code Connection: close} rather than a retry: a retried {@code POST} is a second container
 * whenever the first did arrive, and a fresh connection to a local endpoint costs a handshake per
 * call — a scan makes a few dozen. An upgraded (hijacked) request keeps its own {@code Connection},
 * which the transport sets.
 */
final class OneRequestPerConnection implements DockerHttpClient {

    private final DockerHttpClient delegate;

    OneRequestPerConnection(DockerHttpClient delegate) {
        this.delegate = delegate;
    }

    @Override
    public Response execute(Request request) {
        return delegate.execute(closing(request));
    }

    static Request closing(Request request) {
        boolean named = request.headers().keySet().stream().anyMatch("Connection"::equalsIgnoreCase);
        if (request.hijackedInput() != null || named) {
            return request;
        }
        return Request.builder().from(request).putHeader("Connection", "close").build();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}

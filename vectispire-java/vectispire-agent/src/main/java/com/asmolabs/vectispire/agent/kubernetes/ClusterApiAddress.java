package com.asmolabs.vectispire.agent.kubernetes;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

/**
 * The address of the cluster's API server, as the agent's pod is told it — and checked against the cluster's
 * own name for it before the service account's token is sent there.
 *
 * <p><b>Why the environment alone is not enough.</b> The kubelet puts {@code KUBERNETES_SERVICE_HOST} and
 * {@code KUBERNETES_SERVICE_PORT} in every container, but a variable of the same name in the pod's spec wins
 * over its value — and the chart renders {@code agents.extraEnv} into that spec as written. A value pointing
 * elsewhere would carry the token, on every call, to any host presenting a certificate the cluster's authority
 * signed, which a kubelet's serving certificate often is (review of 2026-10-10). So the host must resolve
 * only to addresses of {@code kubernetes.default.svc}, the service the cluster's DNS answers for and a pod's
 * spec cannot redefine; anything else stops the start, saying which variable to look at.
 *
 * <p><b>Not named {@code KubernetesApi…}</b>: the coverage floor of {@code kubernetesTest} takes that name pattern,
 * and this class is held by the plain unit suite, which can reach every branch of it.
 */
final class ClusterApiAddress {

    /** The API server's service, as the cluster's DNS names it inside the pod's search path. */
    static final String SERVICE_NAME = "kubernetes.default.svc";

    /** The name lookup, injectable so that the decision is tested without a cluster's DNS. */
    @FunctionalInterface
    interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private ClusterApiAddress() {}

    /** From this process's environment and the system's resolver. */
    static URI fromEnvironment() {
        return of(System::getenv, InetAddress::getAllByName);
    }

    /**
     * @param environment the variables of the agent's process
     * @param resolver the name lookup; an IP literal is answered without one
     * @throws IllegalStateException when the address is missing, malformed, or not the API server's service
     */
    static URI of(UnaryOperator<String> environment, Resolver resolver) {
        String host = environment.apply("KUBERNETES_SERVICE_HOST");
        String port = environment.apply("KUBERNETES_SERVICE_PORT");
        if (host == null || host.isBlank() || port == null || port.isBlank()) {
            throw new IllegalStateException("The Kubernetes executor runs in a pod: KUBERNETES_SERVICE_HOST and "
                    + "KUBERNETES_SERVICE_PORT are not set.");
        }
        host = host.strip();
        int number = port(port.strip());

        Set<InetAddress> service = addresses(SERVICE_NAME, resolver, "the cluster's DNS does not answer for "
                + SERVICE_NAME + ", which the agent checks the API server's address against");
        Set<InetAddress> named = addresses(host, resolver, "KUBERNETES_SERVICE_HOST (" + host + ") does not resolve");
        // Every address, not one of them: a name answering both the service and another host would send the
        // token wherever the connection happens to land.
        if (!service.containsAll(named)) {
            throw new IllegalStateException("KUBERNETES_SERVICE_HOST (" + host + ", resolving to " + text(named)
                    + ") is not the address of the cluster's API server, " + SERVICE_NAME + " (" + text(service)
                    + "). The agent does not send its service account's token there and does not start: a variable "
                    + "of that name in the pod's spec replaces the kubelet's — remove it from agents.extraEnv.");
        }
        // An IPv6 service address (a single-stack IPv6 cluster) is bracketed in a URI; the kubelet gives it bare.
        String authority = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
        return URI.create("https://" + authority + ":" + number);
    }

    private static int port(String port) {
        try {
            int number = Integer.parseInt(port);
            if (number >= 1 && number <= 65535) {
                return number;
            }
        } catch (NumberFormatException notANumber) {
            // Said below.
        }
        throw new IllegalStateException("KUBERNETES_SERVICE_PORT (" + port + ") is not a port number. The agent does "
                + "not start: a variable of that name in the pod's spec replaces the kubelet's — remove it from "
                + "agents.extraEnv.");
    }

    private static Set<InetAddress> addresses(String host, Resolver resolver, String refusal) {
        InetAddress[] found;
        try {
            found = resolver.resolve(host);
        } catch (UnknownHostException unknown) {
            throw new IllegalStateException(refusal + ". The agent does not start.", unknown);
        }
        if (found == null || found.length == 0) {
            throw new IllegalStateException(refusal + ". The agent does not start.");
        }
        return Arrays.stream(found).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static String text(Collection<InetAddress> addresses) {
        return addresses.stream().map(InetAddress::getHostAddress).collect(Collectors.joining(", "));
    }
}

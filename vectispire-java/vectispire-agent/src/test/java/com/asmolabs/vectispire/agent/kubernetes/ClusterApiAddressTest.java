package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Whether the agent sends its service account's token to the address its environment names. The cluster's DNS
 * is a map here: what is decided is which answers are accepted, not how a resolver finds them.
 */
class ClusterApiAddressTest {

    private static final Map<String, String> KUBELET = Map.of(
            "KUBERNETES_SERVICE_HOST", "10.43.0.1", "KUBERNETES_SERVICE_PORT", "443");

    @Test
    void theKubeletsAddress_isTheServicesAndIsUsed() {
        URI server = ClusterApiAddress.of(KUBELET::get, dns(Map.of(ClusterApiAddress.SERVICE_NAME, ip("10.43.0.1"))));

        assertThat(server).isEqualTo(URI.create("https://10.43.0.1:443"));
    }

    @Test
    void anOverriddenHost_isRefused_namingTheVariableTheServiceAndTheChartValue() {
        Map<String, String> overridden = Map.of(
                "KUBERNETES_SERVICE_HOST", "10.0.7.12", "KUBERNETES_SERVICE_PORT", "443");

        assertThatThrownBy(() -> ClusterApiAddress.of(overridden::get,
                dns(Map.of(ClusterApiAddress.SERVICE_NAME, ip("10.43.0.1")))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("KUBERNETES_SERVICE_HOST (10.0.7.12")
                .hasMessageContaining("kubernetes.default.svc (10.43.0.1)")
                .hasMessageContaining("agents.extraEnv");
    }

    @Test
    void aHostnameResolvingPartlyOutsideTheService_isRefused() {
        Map<String, String> named = Map.of(
                "KUBERNETES_SERVICE_HOST", "api.example.test", "KUBERNETES_SERVICE_PORT", "443");
        Map<String, InetAddress[]> answers = Map.of(
                ClusterApiAddress.SERVICE_NAME, new InetAddress[] {ip("10.43.0.1")},
                "api.example.test", new InetAddress[] {ip("10.43.0.1"), ip("192.0.2.5")});

        assertThatThrownBy(() -> ClusterApiAddress.of(named::get, answers(answers)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("10.43.0.1, 192.0.2.5");
    }

    @Test
    void aHostnameResolvingOnlyToTheService_isAccepted() {
        Map<String, String> named = Map.of(
                "KUBERNETES_SERVICE_HOST", "kubernetes.default.svc", "KUBERNETES_SERVICE_PORT", "6443");

        URI server = ClusterApiAddress.of(named::get, dns(Map.of(ClusterApiAddress.SERVICE_NAME, ip("10.43.0.1"))));

        assertThat(server).isEqualTo(URI.create("https://kubernetes.default.svc:6443"));
    }

    @Test
    void whenTheClustersDnsDoesNotAnswerForTheService_theAgentDoesNotStart() {
        assertThatThrownBy(() -> ClusterApiAddress.of(KUBELET::get, dns(Map.of())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not answer for kubernetes.default.svc");
    }

    @Test
    void anUnresolvableHost_isRefused() {
        Map<String, String> named = Map.of(
                "KUBERNETES_SERVICE_HOST", "nowhere.invalid", "KUBERNETES_SERVICE_PORT", "443");

        assertThatThrownBy(() -> ClusterApiAddress.of(named::get,
                dns(Map.of(ClusterApiAddress.SERVICE_NAME, ip("10.43.0.1")))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("KUBERNETES_SERVICE_HOST (nowhere.invalid) does not resolve");
    }

    @Test
    void anIpv6ServiceAddress_isBracketed() {
        Map<String, String> v6 = Map.of(
                "KUBERNETES_SERVICE_HOST", "fd00:10:96::1", "KUBERNETES_SERVICE_PORT", "443");

        URI server = ClusterApiAddress.of(v6::get, dns(Map.of(ClusterApiAddress.SERVICE_NAME, ip("fd00:10:96::1"))));

        assertThat(server).isEqualTo(URI.create("https://[fd00:10:96::1]:443"));
        assertThat(server.getHost()).isEqualTo("[fd00:10:96::1]");
    }

    @Test
    void aMissingOrMalformedPort_isRefused() {
        var service = dns(Map.of(ClusterApiAddress.SERVICE_NAME, ip("10.43.0.1")));
        for (String port : new String[] {"https", "0", "65536", "443/tcp"}) {
            Map<String, String> environment = Map.of("KUBERNETES_SERVICE_HOST", "10.43.0.1", "KUBERNETES_SERVICE_PORT", port);
            assertThatThrownBy(() -> ClusterApiAddress.of(environment::get, service))
                    .as(port)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("KUBERNETES_SERVICE_PORT (" + port + ") is not a port number");
        }
        Map<String, String> noPort = Map.of("KUBERNETES_SERVICE_HOST", "10.43.0.1");
        assertThatThrownBy(() -> ClusterApiAddress.of(noPort::get, service))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("are not set");
    }

    /** One address per name, and an IP literal answered as itself, as the system's resolver does. */
    private static ClusterApiAddress.Resolver dns(Map<String, InetAddress> names) {
        return host -> {
            InetAddress found = names.get(host);
            if (found != null) {
                return new InetAddress[] {found};
            }
            return literal(host);
        };
    }

    private static ClusterApiAddress.Resolver answers(Map<String, InetAddress[]> names) {
        return host -> names.containsKey(host) ? names.get(host) : literal(host);
    }

    private static InetAddress[] literal(String host) throws UnknownHostException {
        if (host.chars().anyMatch(Character::isLetter) && !host.contains(":")) {
            throw new UnknownHostException(host);
        }
        return new InetAddress[] {InetAddress.getByName(host)};
    }

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException impossible) {
            throw new AssertionError(impossible);
        }
    }
}

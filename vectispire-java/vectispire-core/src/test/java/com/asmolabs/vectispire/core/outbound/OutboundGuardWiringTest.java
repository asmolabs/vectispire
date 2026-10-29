package com.asmolabs.vectispire.core.outbound;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.core.outbound.internal.OutboundGuardConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The bean, not the class: a guard that knows how to refuse the database is no use if the bean
 * every outbound request goes through was built without telling it where the database is.
 */
@DisplayName("the outbound guard bean")
class OutboundGuardWiringTest {

    @Test
    @DisplayName("refuses the configured database as a destination, whatever the policy")
    void reservesTheDatabase() {
        var guard = new OutboundGuardConfiguration().outboundUrlGuard("jdbc:mysql://127.0.0.1:3306/vectispire", "", "");

        assertThatThrownBy(() -> guard.validate("http://127.0.0.1:3306/", OutboundPolicy.INTERNAL_ALLOWED, "Webhook"))
                .isInstanceOf(UnsafeUrlException.class)
                .hasMessageContaining("the database");
    }

    @Test
    @DisplayName("a repository is not cloned from the database or the daemon, whatever the host list says")
    void aCloneIsRefusedTheReservedEndpoints() {
        // Every other outbound door refused them; a repository URL naming one was cloned from.
        var configuration = new OutboundGuardConfiguration();
        var guard = OutboundGuardConfiguration.guard("tcp://127.0.0.3:2375", "jdbc:mysql://127.0.0.1:3306/vectispire");
        var hosts = configuration.gitHostAllowlist("", guard);

        for (String url : new String[] {
            "http://127.0.0.1:3306/group/project.git",
            "ssh://git@127.0.0.1:33060/group/project.git",
            "https://127.0.0.3:2375/group/project.git"
        }) {
            assertThat(hosts.permits(url)).as(url).isFalse();
            assertThat(hosts.refusal(url)).as(url).containsAnyOf("the database", "the Docker daemon");
        }
        assertThat(hosts.permits("https://127.0.0.1/group/project.git")).isTrue();
        assertThat(configuration.gitHostAllowlist("127.0.0.1", guard).permits("http://127.0.0.1:3306/x.git"))
                .as("listing the host does not open the database's port")
                .isFalse();
    }

    @Test
    @DisplayName("reserves every host of a replicated database, and the X protocol port beside it")
    void reservesEveryDatabaseHost() {
        // java.net.URI reads no host in `mysql:replication://a,b/…`, and the bean reserved nothing.
        var guard = OutboundGuardConfiguration.guard(
                "unix:///var/run/docker.sock", "jdbc:mysql:replication://127.0.0.2:3306,127.0.0.1:3307/vectispire");

        for (String url : new String[] {"http://127.0.0.1:3307/", "http://127.0.0.2:3306/", "http://127.0.0.1:33060/"}) {
            assertThatThrownBy(() -> guard.validate(url, OutboundPolicy.INTERNAL_ALLOWED, "Webhook"))
                    .as(url)
                    .isInstanceOf(UnsafeUrlException.class)
                    .hasMessageContaining("the database");
        }
    }

    @Test
    @DisplayName("in a Kubernetes pod, refuses the cluster's API service, by its address and its port")
    void reservesTheKubernetesApi() {
        // What every pod is given; a forge connection on the internal network may otherwise reach it.
        var guard = new OutboundGuardConfiguration().outboundUrlGuard("", "127.0.0.9", "443");

        assertThatThrownBy(() -> guard.validate("https://127.0.0.9/", OutboundPolicy.INTERNAL_ALLOWED, "Forge connection"))
                .isInstanceOf(UnsafeUrlException.class)
                .hasMessageContaining("the Kubernetes API");
        guard.validate("https://127.0.0.9:8443/", OutboundPolicy.INTERNAL_ALLOWED, "Forge connection");
        assertThatThrownBy(() -> new OutboundGuardConfiguration().outboundUrlGuard("", "127.0.0.9", "https"))
                .as("a port that is not one stops the application rather than reserving nothing")
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("in a Kubernetes pod, refuses the API server's and the kubelet's ports on any address; outside one, not")
    void reservesTheApiServerBehindTheService() {
        // kube-proxy translates the service to the API server's real endpoint, a node address no variable
        // names: reached directly, the service's reservation was walked around.
        var inAPod = new OutboundGuardConfiguration().outboundUrlGuard("", "127.0.0.9", "443");

        for (String url : new String[] {"https://10.0.0.5:6443/api", "https://node-1.cluster.example:6443/",
                "https://10.0.0.7:10250/pods"}) {
            assertThatThrownBy(() -> inAPod.validate(url, OutboundPolicy.INTERNAL_ALLOWED, "Forge connection"))
                    .as(url)
                    .isInstanceOf(UnsafeUrlException.class)
                    .hasMessageContaining("in a Kubernetes cluster");
        }
        inAPod.validate("https://10.0.0.5:8443/", OutboundPolicy.INTERNAL_ALLOWED, "Forge connection");

        var outside = new OutboundGuardConfiguration().outboundUrlGuard("", "", "");
        outside.validate("https://10.0.0.5:6443/", OutboundPolicy.INTERNAL_ALLOWED, "Forge connection");
        outside.validate("https://10.0.0.7:10250/", OutboundPolicy.INTERNAL_ALLOWED, "Forge connection");
    }

    @Test
    @DisplayName("an address whose hosts cannot be read stops the application instead of reserving nothing")
    void anUnreadableAddressIsRefused() {
        assertThatThrownBy(() -> OutboundGuardConfiguration.guard("", "jdbc:mysql+srv://_mysql._tcp.example.com/v"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OutboundGuardConfiguration.guard("ssh://admin@docker-host", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}

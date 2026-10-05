package com.asmolabs.vectispire.core.outbound;

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
    @DisplayName("an address whose hosts cannot be read stops the application instead of reserving nothing")
    void anUnreadableAddressIsRefused() {
        assertThatThrownBy(() -> OutboundGuardConfiguration.guard("", "jdbc:mysql+srv://_mysql._tcp.example.com/v"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OutboundGuardConfiguration.guard("ssh://admin@docker-host", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}

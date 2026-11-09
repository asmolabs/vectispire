package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Policy;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * The queue's tunables as the configuration spells them, bound as the application binds them and
 * handed to the queue's policy — the retry delays above all, which a default elsewhere would hide.
 */
@DisplayName("the scan queue's configuration")
class QueuePropertiesTest {

    private static Policy bound(Map<String, String> properties) {
        CoreConfiguration.QueueProperties queue = new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("vectispire.queue", CoreConfiguration.QueueProperties.class);
        return new CoreConfiguration().scanQueuePolicy(queue);
    }

    @Test
    @DisplayName("unset, the delays are one minute, five and fifteen")
    void theDefaults() {
        assertThat(bound(Map.of()).retryDelays())
                .containsExactly(Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofMinutes(15));
    }

    @Test
    @DisplayName("a comma-separated list, as VECTISPIRE_SCAN_RETRY_DELAYS writes it, reaches the policy")
    void aListReachesThePolicy() {
        assertThat(bound(Map.of("vectispire.queue.retry-delays", "30s,2m")).retryDelays())
                .containsExactly(Duration.ofSeconds(30), Duration.ofMinutes(2));
    }
}

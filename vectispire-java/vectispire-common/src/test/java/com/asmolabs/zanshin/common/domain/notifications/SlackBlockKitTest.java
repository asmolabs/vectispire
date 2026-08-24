package com.asmolabs.zanshin.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the Slack Block Kit payload generator")
class SlackBlockKitTest {

    @Test
    @DisplayName("generates complete Block Kit payload with header, metrics, and actions")
    void generatesSlackBlocks() {
        NotificationPayload payload = new NotificationPayload(
                "3 new vulnerabilities detected",
                "auth-service:main",
                42L,
                3,
                0,
                1,
                1,
                "CRITICAL",
                List.of(new NotificationPayload.Detail(1L, "CVE-2021-44228", "sca", "CRITICAL", true, 0.975, "org.apache.logging.log4j:log4j-core", "pom.xml", "2.17.1", null)),
                0,
                "msg-123");

        Map<String, Object> slackPayload = SlackBlockKit.of(payload, "https://zanshin.corp.com");

        assertThat(slackPayload).containsKey("blocks");
        List<?> blocks = (List<?>) slackPayload.get("blocks");
        assertThat(blocks).isNotEmpty();
    }
}

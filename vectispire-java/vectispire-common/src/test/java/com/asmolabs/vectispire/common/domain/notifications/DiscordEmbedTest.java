package com.asmolabs.vectispire.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the Discord Rich Embed payload generator")
class DiscordEmbedTest {

    @Test
    @DisplayName("generates Discord embed payload with color, fields, and footer")
    void generatesDiscordEmbed() {
        NotificationPayload payload = new NotificationPayload(
                "Critical vulnerability found",
                "payment-gateway:main",
                84L,
                1,
                0,
                0,
                1,
                "HIGH",
                List.of(new NotificationPayload.Detail(2L, "CVE-2022-42889", "sca", "HIGH", true, 0.910, "org.apache.commons:commons-text", "pom.xml", "1.10.0", null)),
                0,
                "msg-456");

        Map<String, Object> discordPayload = DiscordEmbed.of(payload, "https://vectispire.corp.com");

        assertThat(discordPayload).containsKey("embeds");
        List<?> embeds = (List<?>) discordPayload.get("embeds");
        assertThat(embeds).isNotEmpty();
        Map<?, ?> firstEmbed = (Map<?, ?>) embeds.get(0);
        assertThat(firstEmbed.get("color")).isEqualTo(0xDC2626);
    }
}

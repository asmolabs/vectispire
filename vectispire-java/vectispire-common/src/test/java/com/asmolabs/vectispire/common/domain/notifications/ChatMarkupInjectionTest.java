package com.asmolabs.vectispire.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A value the scanned repository wrote cannot become markup in the chat that announces it.
 *
 * <p>Asserted on the JSON actually posted, serialized by a real mapper: what reaches the chat is the
 * string, and the string is where a mention or a link would live.
 */
@DisplayName("markup in a notification's values")
class ChatMarkupInjectionTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** A package whose manifest names it to ping the channel and to carry a link dressed as ours. */
    private static final NotificationPayload HOSTILE = new NotificationPayload(
            "1 new vulnerability detected",
            "shop:main",
            7L,
            1,
            0,
            0,
            0,
            "HIGH",
            List.of(new NotificationPayload.Detail(
                    1L,
                    "CVE-2026-0001",
                    "sca",
                    "HIGH",
                    false,
                    null,
                    "<!channel> @everyone <https://evil.example|Open in Vectispire> [Open in Vectispire](https://evil.example)",
                    "src/{{DATE(2026-01-01T00:00:00Z)}}.js",
                    "1.0.1",
                    null)),
            0,
            "msg-1");

    @Test
    @DisplayName("Slack: every control sequence stays text")
    void slack() throws Exception {
        String posted = JSON.writeValueAsString(SlackBlockKit.of(HOSTILE, null));

        assertThat(posted)
                .doesNotContain("<!channel>")
                .doesNotContain("<https://evil.example|")
                .contains("&lt;!channel&gt;")
                .contains("&lt;https://evil.example|Open in Vectispire&gt;");
    }

    @Test
    @DisplayName("Discord: no masked link, no mass mention, and no mention allowed at all")
    void discord() throws Exception {
        var payload = DiscordEmbed.of(HOSTILE, null);
        String posted = JSON.writeValueAsString(payload);

        assertThat(posted)
                .doesNotContain("[Open in Vectispire](https://evil.example)")
                .doesNotContain("@everyone")
                .contains("\\\\[Open in Vectispire\\\\]\\\\(https://evil.example\\\\)");
        assertThat(payload).containsEntry("allowed_mentions", java.util.Map.of("parse", List.of()));
    }

    @Test
    @DisplayName("Teams: no markdown link, and no card function")
    void teams() throws Exception {
        String posted = JSON.writeValueAsString(TeamsCard.of(HOSTILE, null));

        assertThat(posted)
                .doesNotContain("](https://evil.example)")
                .doesNotContain("{{DATE(")
                .contains("Open in Vectispire]\u200B(https://evil.example)");
    }

    @Test
    @DisplayName("an ordinary value reads as it did")
    void ordinaryValuesAreUnchanged() {
        String ordinary = "org.apache.logging.log4j:log4j-core 2.17.1";

        assertThat(ChatText.slack(ordinary)).isEqualTo(ordinary);
        assertThat(ChatText.teams(ordinary)).isEqualTo(ordinary);
        assertThat(ChatText.discord(ordinary)).isEqualTo(ordinary);
        assertThat(ChatText.slack(null)).isNull();
    }
}

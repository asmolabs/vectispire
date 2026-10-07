package com.asmolabs.vectispire.core.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.outbox.NotificationChannel;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The notification channels the registry switches (decision 0040) are the ones the application delivers
 * through. Read off the running context, by outbox type: a sixth channel bean with no {@link
 * NotificationChannelKind} would be an integration no governor could switch off.
 */
@DisplayName("the notification channels of the integrations' registry")
class NotificationChannelKindTest extends VectispireContextTest {

    @Autowired
    private List<NotificationChannel> channels;

    @Test
    @DisplayName("each channel the application delivers through is a kind, and each kind is a channel")
    void kindsAreTheChannels() {
        assertThat(channels.stream().map(NotificationChannel::type).toList())
                .containsExactlyInAnyOrderElementsOf(
                        Arrays.stream(NotificationChannelKind.values()).map(NotificationChannelKind::outboxType).toList());
    }
}

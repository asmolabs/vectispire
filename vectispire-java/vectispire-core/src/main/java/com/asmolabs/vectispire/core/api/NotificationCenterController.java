package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.services.NotificationTestService;
import com.asmolabs.vectispire.core.services.NotificationTestService.NotificationChannelStatus;
import com.asmolabs.vectispire.core.services.NotificationTestService.NotificationTestResult;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for Multi-Channel Notification Center, status overview, and live dispatch tests.
 */
@RestController
@RequestMapping("/api/v1/notifications")
@RequiresAccount
public class NotificationCenterController {

    private final NotificationTestService notificationTestService;

    public NotificationCenterController(NotificationTestService notificationTestService) {
        this.notificationTestService = notificationTestService;
    }

    @GetMapping("/channels")
    public List<NotificationChannelStatus> getChannels() {
        return notificationTestService.getChannelsStatus();
    }

    // It posts to a configured webhook — somebody else's Slack or Teams. A route that emits
    // outbound traffic on demand belongs to whoever configured the channel.
    @RequiresSecurityLead
    @PostMapping("/test/{channelType}")
    public NotificationTestResult testChannel(@PathVariable String channelType) {
        return notificationTestService.testChannel(channelType);
    }
}

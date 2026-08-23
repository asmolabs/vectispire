package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.NotificationTestService;
import com.asmolabs.zanshin.core.services.NotificationTestService.NotificationChannelStatus;
import com.asmolabs.zanshin.core.services.NotificationTestService.NotificationTestResult;
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

    @PostMapping("/test/{channelType}")
    public NotificationTestResult testChannel(@PathVariable String channelType) {
        return notificationTestService.testChannel(channelType);
    }
}

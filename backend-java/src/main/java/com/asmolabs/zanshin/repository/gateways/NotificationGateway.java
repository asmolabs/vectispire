package com.asmolabs.zanshin.repository.gateways;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class NotificationGateway {

    private final SimpMessagingTemplate messagingTemplate;

    public void sendScanUpdate(Long scanId, String status) {
        log.info("Sending scan update: Scan ID {}, Status {}", scanId, status);
        messagingTemplate.convertAndSend("/topic/scanUpdated", (Object) Map.of(
                "scanId", scanId,
                "status", status
        ));
    }
}

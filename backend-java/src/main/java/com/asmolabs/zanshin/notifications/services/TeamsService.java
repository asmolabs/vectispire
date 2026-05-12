package com.asmolabs.zanshin.notifications.services;

import com.asmolabs.zanshin.settings.services.SettingsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class TeamsService {

    @Lazy
    private final SettingsService settingsService;
    private final RestClient restClient = RestClient.create();

    public void sendVulnerabilityAlert(Long scanId, String projectName, Map<String, Object> summary) {
        Map<String, Object> settings = settingsService.getTeamsSettings();
        Boolean enabled = (Boolean) settings.get("enabled");
        String webhookUrl = (String) settings.get("webhookUrl");

        if (enabled == null || !enabled || webhookUrl == null || !isValidWebhookUrl(webhookUrl)) {
            log.warn("Teams notification disabled or webhook URL is invalid/unsafe.");
            return;
        }

        log.info("Sending Teams notification for scan {}", scanId);

        Map<String, Object> payload = Map.of(
            "type", "message",
            "attachments", List.of(Map.of(
                "contentType", "application/vnd.microsoft.card.adaptive",
                "content", Map.of(
                    "type", "AdaptiveCard",
                    "$schema", "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version", "1.2",
                    "body", List.of(
                        Map.of(
                            "type", "TextBlock",
                            "size", "Medium",
                            "weight", "Bolder",
                            "text", "🚨 Alerte de Sécurité Zanshin - " + projectName,
                            "color", "Attention"
                        ),
                        Map.of(
                            "type", "TextBlock",
                            "text", "Des vulnérabilités ont été détectées lors du scan **" + scanId + "**.",
                            "wrap", true
                        ),
                        Map.of(
                            "type", "FactSet",
                            "facts", List.of(
                                Map.of("title", "Critique", "value", String.valueOf(summary.getOrDefault("critical", 0))),
                                Map.of("title", "Élevé", "value", String.valueOf(summary.getOrDefault("high", 0))),
                                Map.of("title", "Moyen", "value", String.valueOf(summary.getOrDefault("medium", 0))),
                                Map.of("title", "Faible", "value", String.valueOf(summary.getOrDefault("low", 0)))
                            )
                        )
                    ),
                    "actions", List.of(Map.of(
                        "type", "Action.OpenUrl",
                        "title", "Voir le rapport",
                        "url", "http://localhost:4200"
                    ))
                )
            ))
        );

        try {
            restClient.post()
                    .uri(webhookUrl)
                    .body(payload)
                    .retrieve()
                    .toBodilessEntity();
            log.info("Teams notification sent successfully");
        } catch (Exception e) {
            log.error("Failed to send Teams notification: {}", e.getMessage());
        }
    }

    public Map<String, Object> sendTestMessage(String webhookUrl) {
        if (!isValidWebhookUrl(webhookUrl)) {
            throw new RuntimeException("Invalid or unsafe webhook URL provided.");
        }

        Map<String, Object> payload = Map.of(
            "type", "message",
            "attachments", List.of(Map.of(
                "contentType", "application/vnd.microsoft.card.adaptive",
                "content", Map.of(
                    "type", "AdaptiveCard",
                    "$schema", "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version", "1.2",
                    "body", List.of(
                        Map.of(
                            "type", "TextBlock",
                            "size", "Large",
                            "weight", "Bolder",
                            "text", "Zanshin - Test de Connexion Teams"
                        ),
                        Map.of(
                            "type", "TextBlock",
                            "text", "Félicitations ! Votre webhook Teams est correctement configuré.",
                            "wrap", true
                        )
                    )
                )
            ))
        );

        try {
            restClient.post()
                    .uri(webhookUrl)
                    .body(payload)
                    .retrieve()
                    .toBodilessEntity();
            return Map.of("message", "Message de test envoyé");
        } catch (Exception e) {
            log.error("Teams Test failed: {}", e.getMessage());
            throw new RuntimeException("Erreur Teams : " + e.getMessage());
        }
    }

    private boolean isValidWebhookUrl(String url) {
        if (url == null || url.isEmpty()) return false;
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return false;
            
            List<String> allowedDomains = List.of(
                "outlook.office.com",
                "outlook.office365.com",
                "webhook.office.com"
            );
            
            boolean domainAllowed = allowedDomains.stream().anyMatch(host::endsWith);
            return domainAllowed && "https".equalsIgnoreCase(uri.getScheme());
        } catch (Exception e) {
            return false;
        }
    }
}

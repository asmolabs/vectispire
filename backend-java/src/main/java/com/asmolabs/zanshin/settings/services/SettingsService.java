package com.asmolabs.zanshin.settings.services;

import com.asmolabs.zanshin.repository.services.AuditLogService;
import com.asmolabs.zanshin.settings.dto.UpdateAlertSettingsDto;
import com.asmolabs.zanshin.settings.dto.UpdateAuthSettingsDto;
import com.asmolabs.zanshin.settings.dto.UpdateEmailSettingsDto;
import com.asmolabs.zanshin.settings.entities.Setting;
import com.asmolabs.zanshin.settings.repositories.SettingRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SettingsService {

    private final SettingRepository settingRepository;
    private final AuditLogService auditService;

    @PostConstruct
    public void init() {
        initializeSettings();
    }

    private void initializeSettings() {
        Map<String, String> defaultSettings = new HashMap<>();
        defaultSettings.put("AUTH_GITHUB_ENABLED", "false");
        defaultSettings.put("AUTH_KEYCLOAK_ENABLED", "false");
        defaultSettings.put("SMTP_HOST", "");
        defaultSettings.put("SMTP_PORT", "");
        defaultSettings.put("SMTP_USER", "");
        defaultSettings.put("SMTP_PASS", "");
        defaultSettings.put("SMTP_FROM", "");
        defaultSettings.put("ALERT_EMAILS", "");
        defaultSettings.put("ALERT_MIN_SEVERITY", "HIGH");
        defaultSettings.put("TEAMS_WEBHOOK_URL", "");
        defaultSettings.put("TEAMS_ENABLED", "false");

        for (Map.Entry<String, String> entry : defaultSettings.entrySet()) {
            if (!settingRepository.existsById(entry.getKey())) {
                settingRepository.save(new Setting(entry.getKey(), entry.getValue()));
            }
        }
    }

    // --- Auth Settings ---
    public Map<String, Boolean> getAuthSettings() {
        boolean githubEnabled = Boolean.parseBoolean(settingRepository.findById("AUTH_GITHUB_ENABLED").map(Setting::getValue).orElse("false"));
        boolean keycloakEnabled = Boolean.parseBoolean(settingRepository.findById("AUTH_KEYCLOAK_ENABLED").map(Setting::getValue).orElse("false"));

        return Map.of(
            "githubEnabled", githubEnabled,
            "keycloakEnabled", keycloakEnabled
        );
    }

    @Transactional
    public Map<String, Boolean> updateAuthSettings(UpdateAuthSettingsDto dto, String userId) {
        if (dto.githubEnabled() != null) {
            settingRepository.save(new Setting("AUTH_GITHUB_ENABLED", dto.githubEnabled().toString()));
        }
        if (dto.keycloakEnabled() != null) {
            settingRepository.save(new Setting("AUTH_KEYCLOAK_ENABLED", dto.keycloakEnabled().toString()));
        }

        auditService.logAction(userId, "SETTINGS", "UPDATE", "Auth settings updated.");
        return getAuthSettings();
    }

    // --- Email Settings ---
    public Map<String, String> getEmailSettings() {
        return Map.of(
            "smtpHost", settingRepository.findById("SMTP_HOST").map(Setting::getValue).orElse(""),
            "smtpPort", settingRepository.findById("SMTP_PORT").map(Setting::getValue).orElse(""),
            "smtpUser", settingRepository.findById("SMTP_USER").map(Setting::getValue).orElse(""),
            "smtpPass", settingRepository.findById("SMTP_PASS").map(Setting::getValue).orElse(""),
            "smtpFrom", settingRepository.findById("SMTP_FROM").map(Setting::getValue).orElse("")
        );
    }

    @Transactional
    public Map<String, String> updateEmailSettings(UpdateEmailSettingsDto dto, String userId) {
        if (dto.smtpHost() != null) settingRepository.save(new Setting("SMTP_HOST", dto.smtpHost()));
        if (dto.smtpPort() != null) settingRepository.save(new Setting("SMTP_PORT", dto.smtpPort()));
        if (dto.smtpUser() != null) settingRepository.save(new Setting("SMTP_USER", dto.smtpUser()));
        if (dto.smtpPass() != null) settingRepository.save(new Setting("SMTP_PASS", dto.smtpPass()));
        if (dto.smtpFrom() != null) settingRepository.save(new Setting("SMTP_FROM", dto.smtpFrom()));

        auditService.logAction(userId, "SETTINGS", "UPDATE", "Email settings updated.");
        return getEmailSettings();
    }

    // --- Alert Settings ---
    public Map<String, String> getAlertSettings() {
        return Map.of(
            "alertEmails", settingRepository.findById("ALERT_EMAILS").map(Setting::getValue).orElse(""),
            "alertMinSeverity", settingRepository.findById("ALERT_MIN_SEVERITY").map(Setting::getValue).orElse("HIGH")
        );
    }

    @Transactional
    public Map<String, String> updateAlertSettings(UpdateAlertSettingsDto dto, String userId) {
        if (dto.alertEmails() != null) settingRepository.save(new Setting("ALERT_EMAILS", dto.alertEmails()));
        if (dto.alertMinSeverity() != null) settingRepository.save(new Setting("ALERT_MIN_SEVERITY", dto.alertMinSeverity()));
        
        auditService.logAction(userId, "SETTINGS", "UPDATE", "Alert settings updated.");
        return getAlertSettings();
    }

    // --- Teams Settings ---
    public Map<String, Object> getTeamsSettings() {
        String url = settingRepository.findById("TEAMS_WEBHOOK_URL").map(Setting::getValue).orElse("");
        boolean enabled = Boolean.parseBoolean(settingRepository.findById("TEAMS_ENABLED").map(Setting::getValue).orElse("false"));

        return Map.of(
            "webhookUrl", url,
            "enabled", enabled
        );
    }

    @Transactional
    public Map<String, Object> updateTeamsSettings(Map<String, Object> dto, String userId) {
        if (dto.containsKey("webhookUrl")) {
            settingRepository.save(new Setting("TEAMS_WEBHOOK_URL", (String) dto.get("webhookUrl")));
        }
        if (dto.containsKey("enabled")) {
            settingRepository.save(new Setting("TEAMS_ENABLED", dto.get("enabled").toString()));
        }

        auditService.logAction(userId, "SETTINGS", "UPDATE", "Teams settings updated.");
        return getTeamsSettings();
    }
}

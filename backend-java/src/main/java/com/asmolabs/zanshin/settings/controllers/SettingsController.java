package com.asmolabs.zanshin.settings.controllers;

import com.asmolabs.zanshin.mail.services.MailService;
import com.asmolabs.zanshin.notifications.services.TeamsService;
import com.asmolabs.zanshin.settings.dto.UpdateAlertSettingsDto;
import com.asmolabs.zanshin.settings.dto.UpdateAuthSettingsDto;
import com.asmolabs.zanshin.settings.dto.UpdateEmailSettingsDto;
import com.asmolabs.zanshin.settings.services.SettingsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/settings")
@RequiredArgsConstructor
public class SettingsController {

    private final SettingsService settingsService;
    private final MailService mailService;
    private final TeamsService teamsService;

    @GetMapping("/auth")
    public ResponseEntity<Map<String, Boolean>> getAuthSettings() {
        return ResponseEntity.ok(settingsService.getAuthSettings());
    }

    @PutMapping("/auth")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, Boolean>> updateAuthSettings(@RequestBody UpdateAuthSettingsDto updateDto) {
        // In a real app, we would get the user ID from the SecurityContext
        return ResponseEntity.ok(settingsService.updateAuthSettings(updateDto, "system"));
    }

    @GetMapping("/email")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, String>> getEmailSettings() {
        return ResponseEntity.ok(settingsService.getEmailSettings());
    }

    @PutMapping("/email")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, String>> updateEmailSettings(@RequestBody UpdateEmailSettingsDto updateDto) {
        return ResponseEntity.ok(settingsService.updateEmailSettings(updateDto, "system"));
    }

    @GetMapping("/alerting")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, String>> getAlertSettings() {
        return ResponseEntity.ok(settingsService.getAlertSettings());
    }

    @PutMapping("/alerting")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, String>> updateAlertSettings(@RequestBody UpdateAlertSettingsDto updateDto) {
        return ResponseEntity.ok(settingsService.updateAlertSettings(updateDto, "system"));
    }

    @PostMapping("/email/test")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, String>> sendTestEmail(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        mailService.sendTestEmail(email);
        return ResponseEntity.ok(Map.of("message", "Email de test envoyé avec succès"));
    }

    @GetMapping("/teams")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, Object>> getTeamsSettings() {
        return ResponseEntity.ok(settingsService.getTeamsSettings());
    }

    @PutMapping("/teams")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, Object>> updateTeamsSettings(@RequestBody Map<String, Object> updateDto) {
        return ResponseEntity.ok(settingsService.updateTeamsSettings(updateDto, "system"));
    }

    @PostMapping("/teams/test")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
    public ResponseEntity<Map<String, Object>> sendTeamsTest(@RequestBody Map<String, String> body) {
        String webhookUrl = body.get("webhookUrl");
        return ResponseEntity.ok(teamsService.sendTestMessage(webhookUrl));
    }
}

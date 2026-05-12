package com.asmolabs.zanshin.mail.services;

import com.asmolabs.zanshin.settings.services.SettingsService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Properties;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailService {

    @Lazy
    private final SettingsService settingsService;

    private JavaMailSenderImpl createTransporter() {
        Map<String, String> settings = settingsService.getEmailSettings();
        String host = settings.get("smtpHost");
        String portStr = settings.get("smtpPort");

        if (host == null || host.isEmpty() || portStr == null || portStr.isEmpty()) {
            log.warn("SMTP settings are not fully configured. Email will not be sent.");
            return null;
        }

        int port = Integer.parseInt(portStr);
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);

        String user = settings.get("smtpUser");
        String pass = settings.get("smtpPass");
        if (user != null && !user.isEmpty()) {
            mailSender.setUsername(user);
            mailSender.setPassword(pass != null ? pass : "");
        }

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", String.valueOf(user != null && !user.isEmpty()));
        
        if (port == 465) {
            props.put("mail.smtp.ssl.enable", "true");
        } else if (port == 587) {
            props.put("mail.smtp.starttls.enable", "true");
        }
        
        props.put("mail.debug", "false");

        return mailSender;
    }

    public void sendVulnerabilityAlert(Long scanId, String projectName, Map<String, Object> summary, String emails) {
        JavaMailSenderImpl transporter = createTransporter();
        if (transporter == null) return;

        Map<String, String> emailSettings = settingsService.getEmailSettings();
        String fromAddress = emailSettings.getOrDefault("smtpFrom", "noreply@zanshin.local");

        try {
            MimeMessage message = transporter.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromAddress);
            helper.setTo(emails.split(","));
            helper.setSubject("[Zanshin Alert] Vulnérabilités détectées - " + projectName);

            String htmlContent = String.format("""
                <h2>Alerte de Sécurité Zanshin</h2>
                <p>Des vulnérabilités ont été détectées lors du scan <strong>%d</strong> pour le projet <strong>%s</strong>.</p>
                <h3>Résumé des vulnérabilités :</h3>
                <ul>
                  <li><strong>Critique :</strong> %s</li>
                  <li><strong>Élevé :</strong> %s</li>
                  <li><strong>Moyen :</strong> %s</li>
                  <li><strong>Faible :</strong> %s</li>
                  <li><strong>Négligeable :</strong> %s</li>
                  <li><strong>Inconnu :</strong> %s</li>
                </ul>
                <p>Veuillez consulter le tableau de bord Zanshin pour plus de détails.</p>
                """,
                scanId, projectName,
                summary.getOrDefault("critical", 0),
                summary.getOrDefault("high", 0),
                summary.getOrDefault("medium", 0),
                summary.getOrDefault("low", 0),
                summary.getOrDefault("negligible", 0),
                summary.getOrDefault("unknown", 0)
            );

            helper.setText(htmlContent, true);
            transporter.send(message);
            log.info("Alert email sent to {}", emails);
        } catch (MessagingException e) {
            log.error("Failed to send alert email: {}", e.getMessage());
        }
    }

    public void sendTestEmail(String targetEmail) {
        JavaMailSenderImpl transporter = createTransporter();
        if (transporter == null) {
            throw new RuntimeException("SMTP non configuré (Hôte ou Port manquant)");
        }

        Map<String, String> emailSettings = settingsService.getEmailSettings();
        String fromAddress = emailSettings.getOrDefault("smtpFrom", "test@zanshin.local");

        try {
            MimeMessage message = transporter.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromAddress);
            helper.setTo(targetEmail);
            helper.setSubject("[Zanshin] Test de configuration SMTP");
            helper.setText("<h2>Test de configuration Zanshin</h2><p>Félicitations ! Votre configuration SMTP Zanshin fonctionne correctement.</p>", true);

            transporter.send(message);
            log.info("Test email sent to {}", targetEmail);
        } catch (MessagingException e) {
            log.error("SMTP Test failed: {}", e.getMessage());
            throw new RuntimeException("Erreur SMTP : " + e.getMessage());
        }
    }
}

package com.asmolabs.vectispire.core.config;

import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

/**
 * The mail relay, when there is one.
 *
 * <h2>Built here rather than left to auto-configuration</h2>
 *
 * <p>Spring Boot creates a sender as soon as {@code spring.mail.host} is <em>present</em>, and a
 * property mapped from an unset variable is present and empty. That sender exists, answers every
 * injection point, and fails at the first send — so the channel would report itself configured
 * and queue messages that can never leave, filling the outbox with rows whose backoff runs to
 * exhaustion. Conditioning on Vectispire's own variable makes "no relay" mean no bean.
 *
 * <p>It also keeps the naming this project uses everywhere else. An operator reading the
 * variables table should not have to learn a second vocabulary for the one feature that borrows
 * a Spring starter.
 */
@Configuration
@ConditionalOnProperty("vectispire.mail.host")
public class MailConfiguration {

    /**
     * @param starttls on by default. A relay that does not offer it will refuse the upgrade and
     *     the send fails loudly, which is the right outcome: these messages name a company's
     *     unfixed vulnerabilities, and sending them in the clear across a network is a decision
     *     somebody should have to make on purpose
     */
    @Bean
    JavaMailSender mailSender(
            @Value("${vectispire.mail.host}") String host,
            @Value("${vectispire.mail.port:587}") int port,
            @Value("${vectispire.mail.username:}") String username,
            @Value("${vectispire.mail.password:}") String password,
            @Value("${vectispire.mail.starttls:true}") boolean starttls) {

        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(host);
        sender.setPort(port);
        if (!username.isBlank()) {
            sender.setUsername(username);
            sender.setPassword(password);
        }

        Properties properties = sender.getJavaMailProperties();
        properties.put("mail.transport.protocol", "smtp");
        // Only when there is a username: an anonymous internal relay refuses AUTH outright, and
        // asking for it turns a working configuration into a failed send.
        properties.put("mail.smtp.auth", String.valueOf(!username.isBlank()));
        properties.put("mail.smtp.starttls.enable", String.valueOf(starttls));
        // **Timeouts, because the default is none.** A relay that accepts a connection and never
        // answers would hold a relay thread for ever, and the notification tick runs every
        // minute — one unreachable server would eventually hold them all.
        properties.put("mail.smtp.connectiontimeout", "10000");
        properties.put("mail.smtp.timeout", "10000");
        properties.put("mail.smtp.writetimeout", "10000");
        return sender;
    }
}

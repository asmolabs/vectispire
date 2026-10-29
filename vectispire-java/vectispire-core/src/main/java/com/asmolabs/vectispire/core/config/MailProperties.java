package com.asmolabs.vectispire.core.config;

import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * The mail relay, {@code vectispire.mail.*}; read only when a host is set ({@link MailConfiguration}).
 *
 * @param host the relay; absent, there is no sender at all
 * @param port 587, submission, by default
 * @param username empty for an anonymous internal relay, which then is not asked to authenticate
 * @param password read only with a username
 * @param starttls on by default — see {@link MailConfiguration#mailSender}
 */
@Validated
@ConfigurationProperties("vectispire.mail")
public record MailProperties(
        Optional<String> host,
        @DefaultValue("587") int port,
        String username,
        String password,
        @DefaultValue("true") boolean starttls) {

    public MailProperties {
        host = host == null ? Optional.empty() : host;
        username = username == null ? "" : username;
        password = password == null ? "" : password;
    }
}

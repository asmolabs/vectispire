package com.asmolabs.vectispire.core.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Which audit mirror this deployment has.
 *
 * <p><b>Why this sits in {@code services} and not in {@code config}.</b> The layer rule places
 * {@code config} below the services, so it may not see them — which is why every service in this
 * package declares itself with {@code @Service} instead of being built there. A mirror has two
 * shapes rather than one, so the choice needs somewhere to live; it lives beside what it chooses.
 * Putting it in {@code config} compiles and fails {@code ArchitectureTest}, which is how this
 * class came to exist.
 */
@Configuration
public class AuditMirrorConfiguration {

    /**
     * @param mirrorPath where each audit entry is appended as one JSON line, outside the
     *     database. Empty disables it, and {@code /audit-log/verify} reports that it is off — an
     *     integrity control whose state nobody can see is one nobody can rely on
     */
    @ConfigurationProperties("vectispire.audit")
    public record AuditProperties(String mirrorPath) {}

    /**
     * Chosen once, at startup, rather than checked at every append.
     *
     * <p>A mirror that asked "am I configured?" per entry would make the answer changeable
     * halfway through a chain, and "some entries are mirrored" is not a state anybody can verify.
     */
    @Bean
    AuditMirror auditMirror(AuditProperties properties, ObjectMapper json) {
        String configured = properties.mirrorPath() == null ? "" : properties.mirrorPath().trim();
        return configured.isEmpty() ? new AuditMirror.Disabled() : new FileAuditMirror(Path.of(configured), json);
    }
}

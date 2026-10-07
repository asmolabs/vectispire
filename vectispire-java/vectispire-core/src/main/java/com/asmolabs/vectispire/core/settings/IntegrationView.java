package com.asmolabs.vectispire.core.settings;

import java.time.Instant;

/**
 * One integration as the registry answers it (decision 0040).
 *
 * @param key {@code <family>.<name>}, the route's path segment
 * @param family {@code forge}, {@code siem}, {@code ai}, {@code notification} or {@code tracker}
 * @param name the adapter within its family — {@code gitlab}, {@code syslog_tls}, {@code ollama}
 * @param enabled whether the installation may talk to it
 * @param updatedAt when a governor last switched it; null while nobody has
 * @param updatedBy who did; null while nobody has, and for a reader who does not read governance
 */
public record IntegrationView(
        String key, String family, String name, boolean enabled, Instant updatedAt, String updatedBy) {

    /** The same entry without its author, for a reader the governance trail is not shown to. */
    public IntegrationView withoutAuthor() {
        return new IntegrationView(key, family, name, enabled, updatedAt, null);
    }
}

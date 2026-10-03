package com.asmolabs.vectispire.core.reportplugins;

import java.time.Instant;

/**
 * A report plugin switched on for a project, under the entity's property names, and the plugin's name — read
 * by a caller who sees the whole project, so nothing here is more than that caller could already list.
 *
 * @param pluginName null only when the plugin row could not be read; plugins are never deleted
 */
public record ReportPluginActivationView(
        Long id,
        String pluginId,
        String pluginName,
        Long projectId,
        Instant activatedAt,
        String activatedBy) {}

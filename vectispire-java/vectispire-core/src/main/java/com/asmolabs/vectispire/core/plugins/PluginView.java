package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import java.time.Instant;

/**
 * A registered plugin as the routes answer it: the manifest it runs — the same document a governor
 * registers and an agent receives, so the three cannot drift — and the registry's own facts.
 *
 * @param manifestDigest what a scan's task names; changes with any field of the manifest
 * @param enabled false stops every activation at the next scan, without forgetting them
 */
public record PluginView(
        String id,
        String name,
        PluginManifest manifest,
        String manifestDigest,
        boolean enabled,
        Instant createdAt,
        String createdBy,
        Instant updatedAt,
        String updatedBy) {}

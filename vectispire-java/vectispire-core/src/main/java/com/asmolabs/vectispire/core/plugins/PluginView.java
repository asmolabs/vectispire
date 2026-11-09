package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import java.time.Instant;

/**
 * A registered plugin as the routes answer it: the manifest it runs — the same document a governor
 * registers and an agent receives, so the three cannot drift — and the registry's own facts.
 *
 * @param manifestDigest what a scan's task names; changes with any field of the manifest
 * @param enabled false stops every activation at the next scan, without forgetting them
 * @param unsignedWaiver the governor's waiver of the signature requirement for this plugin, or null
 *     for none — without one, a plugin whose manifest declares no signer is refused by every executor
 *     that requires one, which is the default (decision 0017 §9.1)
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
        String updatedBy,
        UnsignedWaiver unsignedWaiver) {

    /**
     * Running the plugin although its manifest declares no signer, decided in writing.
     *
     * @param justification why, as the governor wrote it — shown wherever the waiver is
     * @param waivedBy who granted the waiver in force — the principal, never a name from the request
     */
    public record UnsignedWaiver(String justification, String waivedBy, Instant waivedAt) {}
}

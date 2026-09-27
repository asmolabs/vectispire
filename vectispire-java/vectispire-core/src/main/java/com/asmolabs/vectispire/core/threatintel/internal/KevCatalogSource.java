package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.threatintel.KevCatalog;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Reads CISA's KEV catalogue, from CISA or from the mirror the deployment names.
 *
 * <p>Through {@link OutboundJson}, so through the same guard and the same pinned sender as every
 * other outbound call: the address is resolved, checked against the policy the deployment chose, and
 * connected to as checked; a redirect is refused rather than followed.
 *
 * <p><b>Never inside a transaction.</b> The synchronisation calls this before it opens the one that
 * writes the catalogue, and the scans no longer call it at all — they read what was stored.
 */
@Component
public class KevCatalogSource {

    /**
     * Past the ordinary ceiling on purpose: the catalogue is about a megabyte and a half and grows with
     * every entry CISA adds; 32 MiB is a decade of growth, not an open door. An answer over it is
     * refused by the sender, not truncated — and a truncated one would be refused anyway.
     */
    static final long MAX_BYTES = 32L * 1024 * 1024;

    private final OutboundJson outbound;
    private final ThreatIntelProperties properties;

    public KevCatalogSource(OutboundJson outbound, ThreatIntelProperties properties) {
        this.outbound = outbound;
        this.properties = properties;
    }

    /**
     * The catalogue, whole.
     *
     * @throws RuntimeException when it could not be fetched or is not the whole catalogue — never
     *     an empty one: see {@link KevCatalog}
     */
    public KevCatalog fetch() {
        return KevCatalog.parse(outbound.get(
                        properties.kevCatalogUrl(), properties.kevPolicy(), "KEV catalogue", Map.of(), MAX_BYTES)
                // 404 is "absent" to OutboundJson, and for a catalogue that must exist it is a failure:
                // a mirror that lost the file has not published an empty catalogue.
                .orElseThrow(() -> new KevCatalog.Unreadable("the catalogue was not found at the configured address")));
    }

    /** Where it is read from, for the log line an operator reads when it fails. */
    public String location() {
        return properties.kevCatalogUrl();
    }
}

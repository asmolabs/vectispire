package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where the CISA KEV catalogue is read from.
 *
 * <p><b>A property of the deployment, not a setting of the screen.</b> A closed estate reads the
 * catalogue from a mirror on its own network, which means a private address — and a destination
 * that reaches the private network is one nobody but whoever deploys the control plane should
 * choose: from the settings screen it would let an administrator's session point an outbound call
 * at the database host. Here, it is the operator's environment, as the scanner images are.
 *
 * @param kevUrl the catalogue's URL; blank reads CISA's own
 * @param kevAllowPrivate whether that URL may resolve to a private or loopback address — a mirror
 *     inside the estate. Link-local stays refused whatever this says ({@link OutboundPolicy})
 */
@ConfigurationProperties("vectispire.threat-intel")
public record ThreatIntelProperties(Optional<String> kevUrl, boolean kevAllowPrivate) {

    public ThreatIntelProperties {
        kevUrl = kevUrl == null ? Optional.empty() : kevUrl.map(String::trim).filter(url -> !url.isEmpty());
    }

    /** The URL to read. */
    public String kevCatalogUrl() {
        return kevUrl.orElse(Catalogs.KEV_CATALOG_URL);
    }

    /** How far the outbound guard lets that URL reach. */
    public OutboundPolicy kevPolicy() {
        return kevAllowPrivate ? OutboundPolicy.INTERNAL_ALLOWED : OutboundPolicy.PUBLIC_ONLY;
    }
}

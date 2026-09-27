package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.enrichment.Catalogs;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where the CISA KEV catalogue and FIRST's EPSS file are read from.
 *
 * <p><b>A property of the deployment, not a setting of the screen.</b> A closed estate reads both
 * from a mirror on its own network, which means a private address — and a destination that reaches
 * the private network is one nobody but whoever deploys the control plane should choose: from the
 * settings screen it would let an administrator's session point an outbound call at the database
 * host. Here, it is the operator's environment, as the scanner images are.
 *
 * <p><b>One switch per feed</b>, not one for both: a deployment that mirrors EPSS internally and
 * reads CISA's catalogue from CISA would otherwise have to open the private network to both.
 *
 * @param kevUrl the catalogue's URL; blank reads CISA's own
 * @param kevAllowPrivate whether that URL may resolve to a private or loopback address — a mirror
 *     inside the estate. Link-local stays refused whatever this says ({@link OutboundPolicy})
 * @param epssUrl the EPSS file's URL; blank reads FIRST's own ({@link EpssFile#DEFAULT_URL})
 * @param epssAllowPrivate the same as {@code kevAllowPrivate}, for {@code epssUrl}
 */
@ConfigurationProperties("vectispire.threat-intel")
public record ThreatIntelProperties(
        Optional<String> kevUrl, boolean kevAllowPrivate, Optional<String> epssUrl, boolean epssAllowPrivate) {

    public ThreatIntelProperties {
        kevUrl = present(kevUrl);
        epssUrl = present(epssUrl);
    }

    /** The URL to read. */
    public String kevCatalogUrl() {
        return kevUrl.orElse(Catalogs.KEV_CATALOG_URL);
    }

    /** How far the outbound guard lets that URL reach. */
    public OutboundPolicy kevPolicy() {
        return kevAllowPrivate ? OutboundPolicy.INTERNAL_ALLOWED : OutboundPolicy.PUBLIC_ONLY;
    }

    /** The EPSS file's URL. */
    public String epssFileUrl() {
        return epssUrl.orElse(EpssFile.DEFAULT_URL);
    }

    /** How far the outbound guard lets the EPSS URL reach. */
    public OutboundPolicy epssPolicy() {
        return epssAllowPrivate ? OutboundPolicy.INTERNAL_ALLOWED : OutboundPolicy.PUBLIC_ONLY;
    }

    private static Optional<String> present(Optional<String> url) {
        return url == null ? Optional.empty() : url.map(String::trim).filter(value -> !value.isEmpty());
    }
}

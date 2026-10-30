package com.asmolabs.vectispire.core.siem.internal;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationFamily;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * The SIEM export's answer to the registry (decision 0040 §3): the transport an enabled export sends over
 * is in use, and the governor may not switch it off.
 *
 * <p><b>Refused rather than suspended</b>, unlike a forge: every audited action queues a security event in
 * the outbox, and with the transport off they would have nowhere to go. Held they would pile up unseen by
 * the SOC; abandoned they would be lost in silence — the failure decision 0025 exists to prevent. The
 * security lead points the export elsewhere first, and the collector being left hears it ({@code
 * VECTI-SEC-028}).
 *
 * <p>A disabled export uses no transport, whatever protocol its row still names: nothing is queued for it.
 * Called inside the switch's transaction, after the integration's row is locked; the configuration is
 * read {@code for share} so that a save still open is read as it commits.
 */
@Component
class SiemTransportInUse implements Integrations.InUse {

    private final SiemConfigRepository configs;

    SiemTransportInUse(SiemConfigRepository configs) {
        this.configs = configs;
    }

    @Override
    public Optional<String> use(Integration integration) {
        if (integration.family() != IntegrationFamily.SIEM) {
            return Optional.empty();
        }
        return configs.readLocked(SiemConfigEntity.SINGLETON_ID)
                .filter(SiemConfigEntity::isEnabled)
                .flatMap(config -> SiemProtocol.byName(config.getProtocol()))
                .filter(protocol -> Integration.of(protocol).equals(integration))
                .map(protocol -> "it is the transport the SIEM export sends over. Change the SIEM configuration "
                        + "first — another transport, or the export switched off: the security events queued in "
                        + "the outbox would otherwise have nowhere to go, and be lost in silence.");
    }
}

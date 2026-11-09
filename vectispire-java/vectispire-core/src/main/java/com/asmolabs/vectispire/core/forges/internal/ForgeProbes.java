package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal.Reason;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * The probe of a connection, whatever its forge, with every way it can fail turned into a {@link
 * ForgeConnectionRefusal} — so the service decides on one type what is a security event and what is not.
 *
 * <p><b>The guard's refusal is a security event, a network failure is not.</b> {@code UnsafeUrlException}
 * is the outbound guard saying the address resolves where no forge connection may go — the internal
 * network under {@code PUBLIC_ONLY}, the metadata endpoint, the database or the Docker daemon — and that
 * is how an SSRF attempt through this form looks. A timeout or a certificate the pinned CA did not issue
 * is the administrator's to fix.
 */
@Component
public class ForgeProbes {

    private final Map<ForgeKind, ForgeClient> clients = new EnumMap<>(ForgeKind.class);
    private final ForgeIntegrations integrations;

    ForgeProbes(List<ForgeClient> adapters, ForgeIntegrations integrations) {
        adapters.forEach(adapter -> clients.put(adapter.kind(), adapter));
        this.integrations = integrations;
    }

    /**
     * Presents the token to the forge — the only way a connection's token reaches a forge outside a discovery or a
     * change-review reading, so the registry is asked here, whichever gesture called (decision 0040 §1).
     *
     * @throws ForgeConnectionRefusal for every reason the connection is not made
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException the forge's
     *     integration is disabled: nothing was sent, and nothing is recorded — it is not the forge's refusal
     */
    public ForgeClient.Probe probe(ForgeClient.Target target, String token) {
        integrations.requireEnabled(target.address().edition().kind());
        ForgeClient client = clients.get(target.address().edition().kind());
        if (client == null) {
            throw new IllegalStateException("No adapter for " + target.address().edition().kind());
        }
        try {
            return client.probe(target, token);
        } catch (UnsafeUrlException blocked) {
            throw new ForgeConnectionRefusal(Reason.DESTINATION_BLOCKED, blocked.getMessage()
                    + (target.policy() == OutboundPolicy.PUBLIC_ONLY
                            && !target.address().edition().cloud()
                            ? " If this server is on your internal network, say so on the connection." : ""),
                    blocked);
        } catch (OutboundJson.OutboundFailureException unreachable) {
            throw new ForgeConnectionRefusal(Reason.UNREACHABLE, unreachable.getMessage(), unreachable);
        }
    }
}

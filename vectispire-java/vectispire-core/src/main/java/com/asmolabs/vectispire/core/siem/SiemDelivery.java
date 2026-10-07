package com.asmolabs.vectispire.core.siem;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.CollectorCa;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.outbox.HeldDeliveryException;
import com.asmolabs.vectispire.core.outbox.OutboxHandler;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.siem.internal.SiemSender;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * The relay's handler for {@link SiemEvents#TYPE}: reads the queued event and sends it to the
 * collector configured <em>now</em>.
 *
 * <p><b>The destination is read at send time, not stored on the row</b> — for the reason the outbox
 * gives about webhooks: fixing a typo in the endpoint flushes the queue instead of losing it, and an
 * endpoint written straight into the database is still validated before anything is sent to it.
 *
 * <p>Runs outside any transaction: the relay claims the row in one, sends, and settles it in
 * another. A collector that takes ten seconds to answer holds no lock.
 *
 * <p><b>Never over a disabled transport</b> (decision 0040 §1), and never losing the event for it. The
 * governor cannot switch off the transport an enabled export uses ({@code SiemTransportInUse}, under the
 * registry's lock), so this is the case of a row written by hand — or by a version that did not ask: the
 * event is held, pending with its reason and its attempts uncounted, until the transport is enabled again
 * or the export pointed at one that is.
 */
@Component
public class SiemDelivery implements OutboxHandler {

    private final SiemConfigRepository configs;
    private final SiemSender sender;
    private final Integrations integrations;
    private final EncryptionService encryption;
    private final ObjectMapper json;
    private final Clock clock;

    public SiemDelivery(
            SiemConfigRepository configs,
            SiemSender sender,
            Integrations integrations,
            EncryptionService encryption,
            ObjectMapper json,
            Clock clock) {
        this.configs = configs;
        this.sender = sender;
        this.integrations = integrations;
        this.encryption = encryption;
        this.json = json;
        this.clock = clock;
    }

    @Override
    public String type() {
        return SiemEvents.TYPE;
    }

    /**
     * @throws GoneDestinationException when the export has been switched off or
     *     its endpoint cleared or made unreadable since the event was queued: nothing about waiting
     *     brings a destination back, so the relay abandons the row at once, with this reason
     * @throws HeldDeliveryException when the configured transport is disabled: the row waits, uncounted
     */
    @Override
    public void deliver(UUID messageId, String payload) {
        SiemConfigEntity config = configs.findById(SiemConfigEntity.SINGLETON_ID)
                .filter(SiemConfigEntity::isEnabled)
                .filter(found -> found.getEndpoint() != null && !found.getEndpoint().isBlank())
                .orElseThrow(() -> new GoneDestinationException(
                        "the SIEM export was switched off or its endpoint cleared after this event was queued"));

        SiemProtocol protocol = SiemProtocol.byName(config.getProtocol()).orElseThrow(() ->
                new GoneDestinationException(
                        "the stored SIEM protocol \"" + config.getProtocol() + "\" is not one this version speaks"));
        // Before anything is decrypted or resolved: nothing of a disabled transport runs. Held, not gone —
        // the export still wants these events, and the switch is a gesture away from being turned back.
        Integration transport = Integration.of(protocol);
        if (!integrations.isEnabled(transport)) {
            throw new HeldDeliveryException("the SIEM transport \"" + transport.key() + "\" is disabled on this "
                    + "installation: the event waits until the platform governor enables it, or the SIEM export is "
                    + "pointed at an enabled transport");
        }
        SiemEndpoint endpoint;
        try {
            endpoint = SiemEndpoint.parse(protocol, config.getEndpoint());
        } catch (IllegalArgumentException unreadable) {
            throw new GoneDestinationException(
                    "the stored SIEM endpoint is unusable for " + protocol + ": " + unreadable.getMessage());
        }

        CefEvent event = read(payload).toEvent(messageId.toString()).orElseThrow(() ->
                new IllegalStateException("SIEM event " + messageId + " names an event type this version does not know"));

        String header = protocol.carriesHeaders()
                ? encryption.readSecret(config.getAuthHeader(), SiemExporterService.AUTH_HEADER_CONTEXT,
                        "The SIEM authorization header")
                : null;
        sender.send(endpoint, header, pinnedCa(protocol, config.getTlsCaPem()), event);
    }

    /**
     * The collector CA, checked current <em>now</em>: the save checked it once, and a CA expires
     * while its row sits unchanged. The JDK does not check a trust anchor's own dates, so without
     * this an expired CA would go on being trusted — and a CA the operator let lapse is a
     * configuration to fix, which waiting four hours on the outbox's backoff does not do.
     */
    private Optional<CollectorCa> pinnedCa(SiemProtocol protocol, String stored) {
        if (protocol != SiemProtocol.SYSLOG_TLS || stored == null || stored.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(CollectorCa.parse(stored, clock.instant()));
        } catch (IllegalArgumentException unusable) {
            throw new GoneDestinationException("the pinned SIEM collector CA is unusable: " + unusable.getMessage());
        }
    }

    private SiemEvents.QueuedEvent read(String payload) {
        try {
            return json.readValue(payload, SiemEvents.QueuedEvent.class);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("A queued SIEM event could not be read: " + unreadable.getOriginalMessage(),
                    unreadable);
        }
    }
}

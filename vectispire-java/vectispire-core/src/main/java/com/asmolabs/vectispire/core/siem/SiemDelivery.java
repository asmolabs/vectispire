package com.asmolabs.vectispire.core.siem;

import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.CollectorCa;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.outbox.OutboxHandler;
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
 */
@Component
public class SiemDelivery implements OutboxHandler {

    private final SiemConfigRepository configs;
    private final SiemSender sender;
    private final EncryptionService encryption;
    private final ObjectMapper json;
    private final Clock clock;

    public SiemDelivery(
            SiemConfigRepository configs, SiemSender sender, EncryptionService encryption, ObjectMapper json, Clock clock) {
        this.configs = configs;
        this.sender = sender;
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

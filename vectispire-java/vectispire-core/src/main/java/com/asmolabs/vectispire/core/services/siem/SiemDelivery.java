package com.asmolabs.vectispire.core.services.siem;

import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.repositories.SiemConfigs;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.services.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.services.outbox.OutboxHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    private final SiemConfigs configs;
    private final SiemSender sender;
    private final EncryptionService encryption;
    private final ObjectMapper json;

    public SiemDelivery(SiemConfigs configs, SiemSender sender, EncryptionService encryption, ObjectMapper json) {
        this.configs = configs;
        this.sender = sender;
        this.encryption = encryption;
        this.json = json;
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
        sender.send(endpoint, header, event);
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

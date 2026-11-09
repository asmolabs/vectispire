package com.asmolabs.vectispire.core.tickets.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import java.time.Instant;
import org.springframework.data.domain.Persistable;

/**
 * A tracker delivery already acted on, identified by the SHA-256 of its body.
 *
 * <p><b>Always new, so saving it is an insert.</b> With an assigned identifier a plain save merges:
 * the second copy of a replayed body would update the first row and pass. Declared new, the save is
 * a persist, and the primary key refuses the duplicate in the database — where two copies arriving
 * at once cannot both win.
 */
@Entity
@Table(name = "t_webhook_delivery")
public class WebhookDeliveryEntity implements Persistable<String> {

    @Id
    @Column(name = "body_hash", nullable = false, length = 64)
    private String bodyHash;

    @Column(name = "provider", nullable = false, length = 16)
    private String provider;

    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;

    @Transient
    private boolean fresh = true;

    protected WebhookDeliveryEntity() {}

    public WebhookDeliveryEntity(String bodyHash, String provider, Instant receivedAt) {
        this.bodyHash = bodyHash;
        this.provider = provider;
        this.receivedAt = receivedAt;
    }

    @Override
    public String getId() {
        return bodyHash;
    }

    @Override
    public boolean isNew() {
        return fresh;
    }

    public String getProvider() {
        return provider;
    }

    public Instant getReceivedAt() {
        return receivedAt;
    }
}

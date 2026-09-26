package com.asmolabs.vectispire.core.tickets.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Tracker deliveries already acted on — see {@link WebhookDeliveryEntity}. */
public interface WebhookDeliveries extends JpaRepository<WebhookDeliveryEntity, String> {

    /** Drops what is too old to be worth a replay check, on the write path that fills the table. */
    @Transactional
    @Modifying
    @Query("delete from WebhookDeliveryEntity d where d.receivedAt < :cutoff")
    int deleteBefore(@Param("cutoff") Instant cutoff);
}

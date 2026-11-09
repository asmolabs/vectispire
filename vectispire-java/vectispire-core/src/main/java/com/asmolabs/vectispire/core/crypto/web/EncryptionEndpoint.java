package com.asmolabs.vectispire.core.crypto.web;

import com.asmolabs.vectispire.core.crypto.EncryptionCensus;
import com.asmolabs.vectispire.core.crypto.StoreCensus;
import java.util.List;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.stereotype.Component;

/**
 * {@code GET /actuator/encryption}: which key every sealed store depends on.
 *
 * <p>An Actuator endpoint rather than a route of the API, because it answers an operator in the
 * middle of an operation on the deployment — the rotation of {@code ENCRYPTION_KEY} — and an
 * administrator's session is the one credential the chain lets through to Actuator
 * ({@code ActuatorAccess}). It says how many values stand where, never what they hold.
 */
@Component
@Endpoint(id = "encryption")
public class EncryptionEndpoint {

    private final EncryptionCensus census;

    public EncryptionEndpoint(EncryptionCensus census) {
        this.census = census;
    }

    /**
     * @param rotationFinished no value of any store still needs a previous key: it can leave
     *     {@code VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS}
     */
    public record Report(boolean rotationFinished, List<StoreCensus> stores) {}

    @ReadOperation
    public Report report() {
        List<StoreCensus> stores = census.take();
        return new Report(stores.stream().noneMatch(StoreCensus::dependsOnPreviousKey), stores);
    }
}

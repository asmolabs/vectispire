package com.asmolabs.vectispire.core.crypto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * Every sealed store in one place — what {@code docs/en/KEY_ROTATION.md} reads to say a rotation is
 * finished, served at {@code /actuator/encryption} to an administrator's session.
 *
 * <p><b>And said at start while a value depends on a previous key.</b> The previous key is in the
 * environment for exactly as long as a rotation lasts; an instance starting with rows still under it
 * names the stores, once, so a rotation left half-way is in the log of every restart rather than in
 * the first sign-in refused the day the old key is removed.
 */
@Service
public class EncryptionCensus {

    private static final Logger log = LoggerFactory.getLogger(EncryptionCensus.class);

    private final List<SealedStore> stores;

    public EncryptionCensus(List<SealedStore> stores) {
        this.stores = List.copyOf(stores);
    }

    /** Every store, by name. Outside any transaction: with Vault, reading a seal is a call to it. */
    public List<StoreCensus> take() {
        List<StoreCensus> all = new ArrayList<>();
        stores.forEach(store -> all.addAll(store.census()));
        all.sort(Comparator.comparing(StoreCensus::store));
        return List.copyOf(all);
    }

    @EventListener(ApplicationReadyEvent.class)
    void warnWhileAPreviousKeyIsNeeded() {
        List<StoreCensus> census;
        try {
            census = take();
        } catch (RuntimeException unreadable) {
            // A start is not refused over a report; the endpoint answers the same question on demand.
            log.warn("Could not take the census of the sealed stores at start: {}", unreadable.getMessage());
            return;
        }
        census.stream().filter(StoreCensus::dependsOnPreviousKey).forEach(store -> log.warn(
                "{}: {} value(s) are still sealed under a previous ENCRYPTION_KEY, which must stay in "
                        + "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS until they are re-sealed — {}.",
                store.store(), store.previousKey(), store.reseal()));
        census.stream().filter(store -> store.unreadable() > 0).forEach(store -> log.error(
                "{}: {} value(s) cannot be decrypted by any configured key.", store.store(), store.unreadable()));
    }
}

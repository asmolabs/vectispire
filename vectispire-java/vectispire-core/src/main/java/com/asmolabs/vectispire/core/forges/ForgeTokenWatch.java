package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.forges.ForgeEdition;
import com.asmolabs.vectispire.common.domain.forges.TokenExpiry.Standing;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Notice;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Each forge connection's token expiry, announced fourteen days ahead and when it passes — once per change, never
 * every hour (decision 0037 §2).
 *
 * <p><b>Why.</b> The expiry the forge reported was shown on the connections' list and nowhere else: a token that
 * lapsed left every discovery and every change-review reading of its connection failing until somebody opened that
 * list. A change of what there is to say — {@code expires_soon}, {@code expired}, and back to nothing once the token
 * is replaced — is now published as a {@link TokenAlert}, which {@code notifications} turns into an audit entry (and
 * through it a SIEM event) and a message on each configured channel, as the tracker token's are.
 *
 * <p><b>What was said is kept in a row per connection</b> ({@code forge_token_announced:<id>}, outside the settings
 * catalog), so that a restart says nothing again; it is moved by a conditional update in the transaction that
 * publishes, so that of the instances whose hourly turns notice the same change one announces it, and the message
 * commits with the record that it was said. The row goes with its connection.
 *
 * <p><b>The expiry only.</b> A connection learns its token's expiry when it is probed — created, given another
 * token, another trust — and nothing here calls the forge: the date is compared with the clock. A token the forge
 * refuses fails the discovery that meets it, which says so on the list ({@code token_rejected}).
 */
@Service
public class ForgeTokenWatch {

    private static final Logger log = LoggerFactory.getLogger(ForgeTokenWatch.class);

    /** The settings row holding what was last said of a connection's token. A data contract: it must not move. */
    static final String ANNOUNCED = "forge_token_announced:";

    private final ForgeConnectionRepository connections;
    private final SettingsService settings;
    private final ApplicationEventPublisher events;
    private final Clock clock;

    /** {@code REQUIRES_NEW}: the record that a change was said and what it causes commit together, per connection. */
    private final TransactionOperations separately;

    @Autowired
    public ForgeTokenWatch(
            ForgeConnectionRepository connections,
            SettingsService settings,
            ApplicationEventPublisher events,
            Clock clock,
            PlatformTransactionManager transactions) {
        this(connections, settings, events, clock, requiresNew(transactions));
    }

    ForgeTokenWatch(
            ForgeConnectionRepository connections,
            SettingsService settings,
            ApplicationEventPublisher events,
            Clock clock,
            TransactionOperations separately) {
        this.connections = connections;
        this.settings = settings;
        this.events = events;
        this.clock = clock;
        this.separately = separately;
    }

    private static TransactionTemplate requiresNew(PlatformTransactionManager transactions) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template;
    }

    /**
     * Every connection's token compared with the clock, and each change announced. From the hourly turn.
     *
     * <p>Never throws: a connection whose announcement fails is logged and tried again next hour, and the others
     * are not held back by it.
     *
     * @return how many changes this instance announced
     */
    public int watch() {
        Instant now = clock.instant();
        int announced = 0;
        for (ForgeConnectionEntity connection : connections.findAllByOrderByNameAsc()) {
            try {
                if (watch(connection, now)) {
                    announced++;
                }
            } catch (RuntimeException failed) {
                log.warn("The token of forge connection {} could not be checked: {}", connection.getId(),
                        failed.getMessage());
            }
        }
        return announced;
    }

    /** Forgets what was said of a deleted connection's token. */
    void forget(UUID connectionId) {
        settings.removeInternal(ANNOUNCED + connectionId);
    }

    private boolean watch(ForgeConnectionEntity connection, Instant now) {
        Notice current = Notice.of(false, Standing.of(Optional.ofNullable(connection.getTokenExpiresAt()), now));
        String key = ANNOUNCED + connection.getId();
        Optional<String> stored = settings.internalValue(key);
        if (stored.isEmpty()) {
            // The conditional update needs a row to arbitrate on; whoever inserts it, it starts as "nothing said".
            settings.storeInternalIfAbsent(key, "");
            stored = settings.internalValue(key);
        }
        String expected = stored.orElse("");
        Notice previous = Notice.read(expected);
        if (previous == current) {
            return false;
        }
        TokenAlert alert = new TokenAlert(TokenAlert.Credential.FORGE_CONNECTION, connection.getId().toString(),
                connection.getName(), where(connection), current, previous, connection.getTokenExpiresAt(), null, null,
                now);
        boolean said = Boolean.TRUE.equals(separately.execute(status -> {
            if (!settings.replaceInternal(key, expected, current.wireName())) {
                return false;
            }
            events.publishEvent(alert);
            return true;
        }));
        if (said) {
            switch (current) {
                case EXPIRES_SOON -> log.warn("The token of forge connection {} expires on {}: replace it before then.",
                        connection.getName(), connection.getTokenExpiresAt());
                case EXPIRED, REFUSED -> log.warn("The token of forge connection {} expired on {}: replace it.",
                        connection.getName(), connection.getTokenExpiresAt());
                case NONE -> log.info("The token of forge connection {} is no longer expired nor about to expire.",
                        connection.getName());
            }
        }
        return said;
    }

    /** The forge, for a reader: its edition and address — never the token. */
    private static String where(ForgeConnectionEntity connection) {
        return ForgeEdition.valueOf(connection.getEdition().toUpperCase(Locale.ROOT)).label() + " at "
                + connection.getBaseUrl();
    }
}

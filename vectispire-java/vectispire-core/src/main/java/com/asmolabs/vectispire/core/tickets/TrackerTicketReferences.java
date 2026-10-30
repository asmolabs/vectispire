package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.TrackerState;
import com.asmolabs.vectispire.common.domain.tickets.Tickets;
import com.asmolabs.vectispire.core.issues.TicketReferences;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The tracker's answer to "is this one of my references", for the issue that is about to carry it.
 *
 * <p><b>A reference the configured tracker issues, in the project Vectispire files into.</b> Any
 * string of 64 characters used to be accepted, and it ended up in a URL sent with the integration's
 * token. With no tracker configured a reference is only a label, and nothing is ever sent.
 *
 * <p><b>Not onto a suspended tracker</b> (decision 0040 §3). A reference attached is what the sweep closes
 * with the token once the issue is resolved, and what the tracker's webhook finds the issue by: attaching one
 * while the governor has the tracker switched off would open the synchronisation the switch stopped. Refused
 * 409 {@code integration-disabled}, naming it; the references already attached are kept.
 */
@Service
class TrackerTicketReferences implements TicketReferences {

    private final TicketService tickets;

    TrackerTicketReferences(TicketService tickets) {
        this.tickets = tickets;
    }

    @Override
    public Optional<String> refusal(String reference) {
        tickets.standing().filter(standing -> standing.state() == TrackerState.SUSPENDED).ifPresent(standing -> {
            throw new IntegrationDisabledException(standing.integration());
        });
        TicketProvider provider = tickets.provider();
        if (provider == TicketProvider.NONE
                || Tickets.referencePath(provider, reference, tickets.project()).isPresent()) {
            return Optional.empty();
        }
        return Optional.of("\"" + reference + "\" is not a " + provider.wireName()
                + " reference" + (provider == TicketProvider.JIRA && !tickets.project().isBlank()
                        ? " in project " + tickets.project()
                        : "")
                + ".");
    }
}

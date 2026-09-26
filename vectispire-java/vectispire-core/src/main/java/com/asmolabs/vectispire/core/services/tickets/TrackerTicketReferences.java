package com.asmolabs.vectispire.core.services.tickets;

import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets;
import com.asmolabs.vectispire.core.services.issues.TicketReferences;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The tracker's answer to "is this one of my references", for the issue that is about to carry it.
 *
 * <p><b>A reference the configured tracker issues, in the project Vectispire files into.</b> Any
 * string of 64 characters used to be accepted, and it ended up in a URL sent with the integration's
 * token. With no tracker configured a reference is only a label, and nothing is ever sent.
 */
@Service
class TrackerTicketReferences implements TicketReferences {

    private final TicketService tickets;

    TrackerTicketReferences(TicketService tickets) {
        this.tickets = tickets;
    }

    @Override
    public Optional<String> refusal(String reference) {
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

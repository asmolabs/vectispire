package com.asmolabs.vectispire.core.outbox;

import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.VectispireContextTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Every outbox type the running application relays — {@code vectispire-rust/reference/outbox/registry.json}.
 *
 * <p><b>The Rust relay is held back until its registry equals this one.</b> A relay that does not know a type retries
 * its rows and then abandons them; on a database Java wrote, that destroys every pending message of the types the port
 * has not reached yet. So the list the Rust binary compares itself with is read from the started application — the
 * beans Spring hands {@link OutboxService} — and not from the sources, where a handler whose {@code @Component} was
 * lost would still be counted.
 */
class OutboxRegistryReferenceSetTest extends VectispireContextTest {

    @Autowired
    private List<OutboxHandler> handlers;

    @Autowired
    private List<NotificationChannel> channels;

    @Test
    void theTypesTheRelayDelivers() {
        var out = RustReference.object();
        var handled = out.putArray("handlers");
        handlers.stream().map(OutboxHandler::type).sorted().forEach(handled::add);
        var routed = out.putArray("channels");
        channels.stream().map(NotificationChannel::type).sorted().forEach(routed::add);
        RustReference.expect("outbox/registry.json", out, OutboxRegistryReferenceSetTest.class);
    }
}

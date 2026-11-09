package com.asmolabs.vectispire.core.tickets.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("which webhook refusals are audited")
class WebhookRefusalsTest {

    /** A clock the test moves by hand. */
    private static final class Hand extends Clock {
        private Instant now = Instant.parse("2026-09-25T10:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Test
    @DisplayName("one address: the first refusal and the one reaching the ceiling, nothing between")
    void firstAndCeiling() {
        WebhookRefusals refusals = new WebhookRefusals(new Hand());

        long audited = IntStream.rangeClosed(1, 50)
                .mapToObj(i -> refusals.refused("198.51.100.7"))
                .filter(Optional::isPresent)
                .count();

        assertThat(audited).as("fifty refusals, two entries").isEqualTo(2);
    }

    @Test
    @DisplayName("a new window starts the count again")
    void aNewWindowCountsAgain() {
        Hand clock = new Hand();
        WebhookRefusals refusals = new WebhookRefusals(clock);

        assertThat(refusals.refused("198.51.100.7")).isPresent();
        assertThat(refusals.refused("198.51.100.7")).isEmpty();

        clock.now = clock.now.plus(WebhookRefusals.WINDOW);
        assertThat(refusals.refused("198.51.100.7")).isPresent();
    }

    @Test
    @DisplayName("rotating addresses cannot write more than the budget, and the last entry says so")
    void rotatingAddressesAreBudgeted() {
        WebhookRefusals refusals = new WebhookRefusals(new Hand());

        java.util.List<String> notes = IntStream.range(0, 500)
                .mapToObj(i -> refusals.refused("2001:db8::" + Integer.toHexString(i)))
                .flatMap(Optional::stream)
                .toList();

        assertThat(notes).hasSize(WebhookRefusals.GLOBAL_BUDGET);
        assertThat(notes.getLast()).contains("not recorded again");
    }
}

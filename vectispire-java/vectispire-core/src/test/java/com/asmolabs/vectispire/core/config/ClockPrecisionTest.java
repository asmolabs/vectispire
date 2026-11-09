package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The application's clock reads no finer than the engines store, on every platform.
 *
 * <p>A report's signed provenance and an import's answer each disagreed with the row they describe
 * in CI only, because the Linux clock reads nanoseconds and the engines keep microseconds. This
 * asserts the bean itself, so it fails on macOS too, where the system clock already stops at the
 * microsecond and would hide a revert.
 */
@DisplayName("the application clock")
class ClockPrecisionTest {

    @Test
    @DisplayName("never reads below the microsecond, whatever the platform's clock gives")
    void ticksInMicroseconds() {
        Clock clock = new CoreConfiguration().clock();

        assertThat(CoreConfiguration.MICROSECOND.toNanos()).isEqualTo(1_000);
        assertThat(clock.getZone().getId()).isEqualTo("Z");
        // Clock.tick is what guarantees it; a plain system clock fails this on any platform.
        assertThat(clock).isEqualTo(Clock.tick(Clock.systemUTC(), CoreConfiguration.MICROSECOND));
        for (int i = 0; i < 1_000; i++) {
            assertThat(clock.instant().getNano() % 1_000).isZero();
        }
    }
}

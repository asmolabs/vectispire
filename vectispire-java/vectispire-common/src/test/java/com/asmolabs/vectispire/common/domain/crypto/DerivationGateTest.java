package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the bound on password derivations running at once")
class DerivationGateTest {

    private static final long MIB = 1024L * 1024L;

    @Test
    @DisplayName("past the bound, a derivation waits its turn and is then refused, saying when to retry")
    void saturationIsRefused() throws Exception {
        DerivationGate gate = new DerivationGate(1, Duration.ofMillis(50));
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CompletableFuture<String> holder = CompletableFuture.supplyAsync(() -> gate.run(() -> {
            holding.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return "held";
        }));
        assertThat(holding.await(10, TimeUnit.SECONDS)).isTrue();

        long started = System.nanoTime();
        assertThatThrownBy(() -> gate.run(() -> "second"))
                .isInstanceOfSatisfying(DerivationsSaturated.class,
                        saturated -> assertThat(saturated.retryAfter()).isEqualTo(Duration.ofSeconds(1)));
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isGreaterThanOrEqualTo(Duration.ofMillis(50));

        release.countDown();
        assertThat(holder.get(10, TimeUnit.SECONDS)).isEqualTo("held");
        assertThat(gate.run(() -> "after")).isEqualTo("after");
    }

    /** A derivation that throws — a malformed parameter, an out-of-memory — must not keep its permit. */
    @Test
    @DisplayName("a permit is given back when the derivation throws")
    void aFailedDerivationGivesItsPermitBack() {
        DerivationGate gate = new DerivationGate(1, Duration.ofMillis(50));

        for (int i = 0; i < 3; i++) {
            assertThatThrownBy(() -> gate.run(() -> {
                throw new IllegalStateException("derivation failed");
            })).isInstanceOf(IllegalStateException.class);
        }

        assertThat(gate.available()).isEqualTo(1);
        assertThat(gate.run(() -> "next")).isEqualTo("next");
    }

    @Test
    @DisplayName("the hasher runs every derivation under the bound in force")
    void theHasherIsBounded() throws Exception {
        DerivationGate shipped = PasswordHasher.gate();
        DerivationGate closed = new DerivationGate(1, Duration.ofMillis(20));
        try {
            PasswordHasher.bound(closed);
            String hash = PasswordHasher.hash("a passphrase");
            CountDownLatch release = new CountDownLatch(1);
            CountDownLatch holding = new CountDownLatch(1);
            CompletableFuture<Object> holder = CompletableFuture.supplyAsync(() -> closed.run(() -> {
                holding.countDown();
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                return null;
            }));
            try {
                assertThat(holding.await(10, TimeUnit.SECONDS)).isTrue();
                assertThatThrownBy(() -> PasswordHasher.verify("a passphrase", hash))
                        .isInstanceOf(DerivationsSaturated.class);
                assertThatThrownBy(() -> PasswordHasher.hash("another")).isInstanceOf(DerivationsSaturated.class);
            } finally {
                release.countDown();
                holder.join();
            }
            assertThat(PasswordHasher.verify("a passphrase", hash)).isTrue();
        } finally {
            PasswordHasher.bound(shipped);
        }
    }

    @Test
    @DisplayName("an unset bound reads as the shipped one, never as zero")
    void unsetReadsAsShipped() {
        assertThat(new DerivationGate(0, null).permits()).isEqualTo(DerivationGate.defaultPermits());
        assertThat(new DerivationGate(-3, Duration.ZERO).await()).isEqualTo(DerivationGate.DEFAULT_WAIT);
        assertThat(new DerivationGate(5, Duration.ofMillis(300)).permits()).isEqualTo(5);
    }

    @Test
    @DisplayName("the shipped bound is one per processor, at least two, and never more than a quarter of the heap holds")
    void shippedBound() {
        assertThat(DerivationGate.defaultPermits(1, 4096 * MIB)).isEqualTo(2);
        assertThat(DerivationGate.defaultPermits(8, 4096 * MIB)).isEqualTo(8);
        // The shipped Helm chart: 75% of 2 GiB, on a node reporting 64 processors.
        assertThat(DerivationGate.defaultPermits(64, 1536 * MIB)).isEqualTo(20);
        assertThat(DerivationGate.defaultPermits(64, 1536 * MIB) * PasswordHasher.derivationBytes())
                .isLessThanOrEqualTo(1536 * MIB / 4);
        assertThat(DerivationGate.defaultPermits(4, 32 * MIB)).isEqualTo(1);
    }
}

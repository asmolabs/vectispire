package com.asmolabs.vectispire.common.domain.scans;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the kind of a failure that stopped a scan")
class FailureKindTest {

    /** A failure that says what it is, the way a clone's or a task's does. */
    private static final class Declared extends RuntimeException implements ClassifiedFailure {
        private final FailureKind kind;

        Declared(FailureKind kind, Throwable cause) {
            super("declared", cause);
            this.kind = kind;
        }

        @Override
        public FailureKind failureKind() {
            return kind;
        }
    }

    @Test
    @DisplayName("a report without a kind is transient, so an older agent keeps the rule it had")
    void absentIsTransient() {
        assertThat(FailureKind.fromWire(null)).isEqualTo(FailureKind.TRANSIENT);
        assertThat(FailureKind.fromWire("")).isEqualTo(FailureKind.TRANSIENT);
        assertThat(FailureKind.fromWire("transient")).isEqualTo(FailureKind.TRANSIENT);
    }

    @Test
    @DisplayName("permanent is read as written, and nothing else is read as permanent")
    void onlyPermanentIsPermanent() {
        assertThat(FailureKind.fromWire("permanent")).isEqualTo(FailureKind.PERMANENT);
        assertThat(FailureKind.fromWire(" Permanent ")).isEqualTo(FailureKind.PERMANENT);
        // A later agent's word this version cannot read must not fail a scan for good.
        assertThat(FailureKind.fromWire("fatal")).isEqualTo(FailureKind.TRANSIENT);
        assertThat(FailureKind.fromWire("permanently")).isEqualTo(FailureKind.TRANSIENT);
    }

    @Test
    @DisplayName("the wire names are the report's")
    void wireNames() {
        assertThat(FailureKind.PERMANENT.wireName()).isEqualTo("permanent");
        assertThat(FailureKind.TRANSIENT.wireName()).isEqualTo("transient");
    }

    @Test
    @DisplayName("an exception nobody classified is transient")
    void unclassifiedIsTransient() {
        assertThat(FailureKind.of(new IllegalStateException("¯\\_(ツ)_/¯"))).isEqualTo(FailureKind.TRANSIENT);
        assertThat(FailureKind.of(null)).isEqualTo(FailureKind.TRANSIENT);
    }

    @Test
    @DisplayName("the kind is found along the causes, the nearest declaration winning")
    void readsTheCauses() {
        Throwable wrapped = new RuntimeException("runner", new Declared(FailureKind.PERMANENT, null));
        assertThat(FailureKind.of(wrapped)).isEqualTo(FailureKind.PERMANENT);

        Throwable overridden = new Declared(FailureKind.TRANSIENT, new Declared(FailureKind.PERMANENT, null));
        assertThat(FailureKind.of(overridden)).isEqualTo(FailureKind.TRANSIENT);
    }

    @Test
    @DisplayName("a cycle in the causes ends the walk rather than the thread")
    void survivesACycle() {
        RuntimeException first = new RuntimeException("first");
        RuntimeException second = new RuntimeException("second", first);
        first.initCause(second);

        assertThat(FailureKind.of(first)).isEqualTo(FailureKind.TRANSIENT);
    }
}

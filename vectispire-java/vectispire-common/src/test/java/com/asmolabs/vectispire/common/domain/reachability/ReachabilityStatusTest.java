package com.asmolabs.vectispire.common.domain.reachability;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ReachabilityStatus domain representation")
class ReachabilityStatusTest {

    @Test
    @DisplayName("parses wire names accurately")
    void parsesWireNames() {
        assertThat(ReachabilityStatus.fromWire("reachable")).isEqualTo(ReachabilityStatus.REACHABLE);
        assertThat(ReachabilityStatus.fromWire("REACHABLE")).isEqualTo(ReachabilityStatus.REACHABLE);
        assertThat(ReachabilityStatus.fromWire("unreachable")).isEqualTo(ReachabilityStatus.UNREACHABLE);
        assertThat(ReachabilityStatus.fromWire("unknown")).isEqualTo(ReachabilityStatus.UNKNOWN);
        assertThat(ReachabilityStatus.fromWire(null)).isEqualTo(ReachabilityStatus.UNKNOWN);
        assertThat(ReachabilityStatus.fromWire("")).isEqualTo(ReachabilityStatus.UNKNOWN);
    }

    @Test
    @DisplayName("formats wire names in lowercase")
    void formatsWireNames() {
        assertThat(ReachabilityStatus.REACHABLE.wireName()).isEqualTo("reachable");
        assertThat(ReachabilityStatus.UNREACHABLE.wireName()).isEqualTo("unreachable");
        assertThat(ReachabilityStatus.UNKNOWN.wireName()).isEqualTo("unknown");
    }
}

package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** An IPv6 client is its /64 (the audit of 10 October 2026); an IPv4 client is its address. */
@DisplayName("the budget an address spends")
class ClientBucketsTest {

    @Test
    @DisplayName("two addresses of one /64 share a bucket, another /64 does not")
    void oneSlash64IsOneClient() {
        assertThat(ClientBuckets.of("2001:db8:1:2::1")).isEqualTo(ClientBuckets.of("2001:db8:1:2:abcd:ef01:2345:6789"));
        assertThat(ClientBuckets.of("2001:db8:1:2::1")).isEqualTo(ClientBuckets.of("[2001:db8:1:2::ffff]"));
        assertThat(ClientBuckets.of("2001:db8:1:2::1")).isNotEqualTo(ClientBuckets.of("2001:db8:1:3::1"));
    }

    @Test
    @DisplayName("an IPv4 client, wrapped or not, is its address; what is not an address stays as it came")
    void ipv4AndTheRest() {
        assertThat(ClientBuckets.of("192.0.2.10")).isEqualTo("192.0.2.10");
        assertThat(ClientBuckets.of("192.0.2.10")).isNotEqualTo(ClientBuckets.of("192.0.2.11"));
        assertThat(ClientBuckets.of("::ffff:192.0.2.10")).isEqualTo("192.0.2.10");
        assertThat(ClientBuckets.of("unknown")).isEqualTo("unknown");
    }

    @Test
    @DisplayName("the login client counter is keyed on the bucket")
    void theLoginCounterFollows() {
        assertThat(LoginThrottle.clientKey("2001:db8:1:2::1")).isEqualTo(LoginThrottle.clientKey("2001:db8:1:2::2"));
    }
}

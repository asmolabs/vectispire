package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the address a forwarded hop names")
class AddressLiteralsTest {

    @Test
    @DisplayName("an IPv4 address, with or without its port, is the address")
    void ipv4() {
        assertThat(AddressLiterals.of("198.51.100.7")).contains("198.51.100.7");
        assertThat(AddressLiterals.of(" 198.51.100.7:51234 ")).contains("198.51.100.7");
    }

    @Test
    @DisplayName("a bracketed IPv6 address, with or without its port, is the address")
    void bracketedIpv6() {
        assertThat(AddressLiterals.of("[2001:db8::7]:51234")).contains("2001:db8::7");
        assertThat(AddressLiterals.of("[2001:db8::7]")).contains("2001:db8::7");
    }

    @Test
    @DisplayName("a bare IPv6 address keeps its last group: its colons are not a port")
    void bareIpv6() {
        assertThat(AddressLiterals.of("2001:db8::7")).contains("2001:db8::7");
        assertThat(AddressLiterals.of("2001:db8:0:0:1:2:3:8080")).contains("2001:db8:0:0:1:2:3:8080");
        assertThat(AddressLiterals.of("::1")).contains("::1");
        assertThat(AddressLiterals.of("2001:db8::1:8080")).contains("2001:db8::1:8080");
    }

    @Test
    @DisplayName("what is not an address literal is nothing")
    void notALiteral() {
        assertThat(AddressLiterals.of("unknown")).isEmpty();
        assertThat(AddressLiterals.of("_hidden")).isEmpty();
        assertThat(AddressLiterals.of("example.org")).isEmpty();
        assertThat(AddressLiterals.of("example.org:443")).isEmpty();
        assertThat(AddressLiterals.of("198.51.100.7:")).isEmpty();
        assertThat(AddressLiterals.of("198.51.100.7:port")).isEmpty();
        assertThat(AddressLiterals.of("198.51.100.7:1234567")).isEmpty();
        assertThat(AddressLiterals.of("[198.51.100.7]:80")).isEmpty();
        assertThat(AddressLiterals.of("[2001:db8::7]junk")).isEmpty();
        assertThat(AddressLiterals.of("[2001:db8::7")).isEmpty();
        assertThat(AddressLiterals.of("")).isEmpty();
        assertThat(AddressLiterals.of(null)).isEmpty();
    }
}

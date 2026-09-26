package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("reading a SIEM endpoint for its protocol")
class SiemEndpointTest {

    @Test
    @DisplayName("a webhook is an http(s) URL")
    void webhook() {
        assertThat(SiemEndpoint.parse(SiemProtocol.WEBHOOK, " https://siem.example.com/cef "))
                .isEqualTo(new SiemEndpoint.Webhook("https://siem.example.com/cef"));
        assertThatThrownBy(() -> SiemEndpoint.parse(SiemProtocol.WEBHOOK, "collector.example.com:514"))
                .hasMessageContaining("http(s) URL");
        assertThatThrownBy(() -> SiemEndpoint.parse(SiemProtocol.WEBHOOK, "ftp://x/"))
                .hasMessageContaining("http(s) URL");
    }

    @Test
    @DisplayName("a syslog endpoint is host:port, a name or an IPv4")
    void syslog() {
        assertThat(SiemEndpoint.parse(SiemProtocol.SYSLOG_TLS, "collector.example.com:6514"))
                .isEqualTo(new SiemEndpoint.Syslog(SiemProtocol.SYSLOG_TLS, "collector.example.com", 6514));
        assertThat(SiemEndpoint.parse(SiemProtocol.SYSLOG_UDP, "10.0.0.5:514"))
                .isEqualTo(new SiemEndpoint.Syslog(SiemProtocol.SYSLOG_UDP, "10.0.0.5", 514));
    }

    @Test
    @DisplayName("an IPv6 collector is written in brackets, which are not part of the host")
    void ipv6() {
        assertThat(SiemEndpoint.parse(SiemProtocol.SYSLOG_TCP, "[2001:db8::1]:514"))
                .isEqualTo(new SiemEndpoint.Syslog(SiemProtocol.SYSLOG_TCP, "2001:db8::1", 514));
        assertThatThrownBy(() -> SiemEndpoint.parse(SiemProtocol.SYSLOG_TCP, "2001:db8::1:514"))
                .hasMessageContaining("[address]:port");
        assertThatThrownBy(() -> SiemEndpoint.parse(SiemProtocol.SYSLOG_TCP, "[not-v6]:514"))
                .hasMessageContaining("not an IPv6 address");
    }

    @ParameterizedTest(name = "refuses \"{0}\" as a syslog endpoint")
    @ValueSource(strings = {
        "syslog+tls://collector.example.com:6514",
        "tcp://collector:514",
        "collector.example.com",
        "collector.example.com:",
        "collector.example.com:0",
        "collector.example.com:65536",
        "collector.example.com:５１４",
        "collector.example.com:514/path",
        ":514",
        "bad_host!:514",
        "host name:514"
    })
    void refusesMalformedSyslog(String endpoint) {
        assertThatThrownBy(() -> SiemEndpoint.parse(SiemProtocol.SYSLOG_TLS, endpoint))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("an empty endpoint is refused for every protocol")
    void emptyIsRefused() {
        for (SiemProtocol protocol : SiemProtocol.values()) {
            assertThatThrownBy(() -> SiemEndpoint.parse(protocol, "  ")).hasMessageContaining("required");
        }
    }
}

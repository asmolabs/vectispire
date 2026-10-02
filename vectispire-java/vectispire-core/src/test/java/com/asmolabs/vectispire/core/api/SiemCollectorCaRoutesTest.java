package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.outbox.GoneDestinationException;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemDelivery;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * A syslog-over-TLS collector verified against its own CA, pinned in the SIEM configuration rather
 * than imported into the runtime's trust store — over a real TLS socket on loopback, whose
 * certificate only that CA issued.
 */
@DisplayName("the SIEM collector's pinned CA")
class SiemCollectorCaRoutesTest extends ApiTestBase {

    @Autowired
    private SiemConfigRepository configs;

    @Autowired
    private SettingsService settings;

    @Autowired
    private SiemDelivery delivery;

    @BeforeEach
    void privateCollectors() {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
    }

    @AfterEach
    void publicOnly() {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "false");
    }

    @Test
    @DisplayName("the connection test reaches a collector its pinned CA vouches for, and only then")
    void theTestVerifiesAgainstThePinnedCa() throws Exception {
        CollectorPki pki = CollectorPki.create("Corp SOC Root");
        try (SSLServerSocket collector = pki.listen()) {
            String endpoint = "127.0.0.1:" + collector.getLocalPort();

            // The runtime's store does not hold the private CA: refused, whatever else holds.
            CompletableFuture<byte[]> ignored = CollectorPki.received(collector);
            test(endpoint, "").andExpect(jsonPath("$.success").value(false));
            ignored.get(10, TimeUnit.SECONDS);

            // Another CA pinned: refused too — pinning replaces the store, it does not add to it.
            ignored = CollectorPki.received(collector);
            test(endpoint, CollectorPki.create("Someone Else").caPem).andExpect(jsonPath("$.success").value(false));
            ignored.get(10, TimeUnit.SECONDS);

            CompletableFuture<byte[]> received = CollectorPki.received(collector);
            test(endpoint, pki.caPem).andExpect(jsonPath("$.success").value(true));
            assertThat(new String(received.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8))
                    .contains(" VECTI-SEC-999 - CEF:0|Vectispire|ASPM|");
        }
    }

    @Test
    @DisplayName("a queued event is delivered over TLS to the collector the stored CA vouches for")
    void aQueuedEventUsesTheStoredCa() throws Exception {
        CollectorPki pki = CollectorPki.create("Corp SOC Root");
        try (SSLServerSocket collector = pki.listen()) {
            save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "127.0.0.1:" + collector.getLocalPort(),
                            "tlsCaPem", pki.caPem))
                    .andExpect(status().isOk());

            CompletableFuture<byte[]> received = CollectorPki.received(collector);
            delivery.deliver(UUID.randomUUID(), payload());

            assertThat(new String(received.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8))
                    .contains(" VECTI-SEC-019 - CEF:0|Vectispire|ASPM|");
        }
    }

    @Test
    @DisplayName("a stored CA that has expired since its save is not trusted: the event is abandoned with the reason")
    void anExpiredStoredCaIsRefusedAtDelivery() throws Exception {
        CollectorPki lapsed = CollectorPki.create(
                "Lapsed Root", Instant.now().minus(Duration.ofDays(400)), Instant.now().minus(Duration.ofDays(1)));
        SiemConfigEntity row = new SiemConfigEntity();
        row.setEnabled(true);
        row.setProtocol("SYSLOG_TLS");
        row.setEndpoint("127.0.0.1:6514");
        // Written past the save, as a CA that was current when saved and lapsed since would be.
        row.setTlsCaPem(lapsed.caPem);
        configs.save(row);

        assertThatThrownBy(() -> delivery.deliver(UUID.randomUUID(), payload()))
                .isInstanceOf(GoneDestinationException.class)
                .hasMessageContaining("collector CA")
                .hasMessageContaining("expired");
        mvc.perform(authenticated(get("/api/v1/siem/config"), asAdmin()))
                .andExpect(jsonPath("$.tlsCaSubject").value("CN=Lapsed Root"));
    }

    @Test
    @DisplayName("the save reads the CA: a leaf, an expired CA, a CA for another protocol are refused in words")
    void theSaveRefusesWhatIsNotACurrentCa() throws Exception {
        CollectorPki expired = CollectorPki.create(
                "Old Root", Instant.now().minus(Duration.ofDays(400)), Instant.now().minus(Duration.ofDays(1)));

        assertThat(detailOf(save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "c.example.com:6514",
                        "tlsCaPem", expired.caPem)).andExpect(status().isBadRequest()).andReturn()))
                .contains("expired on");
        assertThat(detailOf(save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "c.example.com:6514",
                        "tlsCaPem", "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n"
                                + "-----END PRIVATE KEY-----")).andExpect(status().isBadRequest()).andReturn()))
                .contains("PEM");
        CollectorPki pki = CollectorPki.create("Corp Root");
        assertThat(detailOf(save(Map.of("protocol", "SYSLOG_TCP", "endpoint", "c.example.com:514",
                        "tlsCaPem", pki.caPem)).andExpect(status().isBadRequest()).andReturn()))
                .contains("syslog over TLS only");
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID)).isEmpty();
    }

    @Test
    @DisplayName("a pinned CA is shown, kept by a save that omits it, removed by a blank one and by leaving TLS")
    void theCaLifecycle() throws Exception {
        CollectorPki pki = CollectorPki.create("Corp SOC Root");
        save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "c.example.com:6514", "tlsCaPem", pki.caPem))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tlsCaSubject").value("CN=Corp SOC Root"))
                .andExpect(jsonPath("$.tlsCaNotAfter").isNotEmpty())
                .andExpect(jsonPath("$.tlsCaPem").value(pki.caPem.trim()));

        // A client written before the field existed does not unpin it.
        save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "c.example.com:6514", "minSeverity", "LOW"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tlsCaSubject").value("CN=Corp SOC Root"));

        save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "c.example.com:6514", "tlsCaPem", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tlsCaPem").isEmpty());
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getTlsCaPem()).isNull();

        save(Map.of("protocol", "SYSLOG_TLS", "endpoint", "c.example.com:6514", "tlsCaPem", pki.caPem))
                .andExpect(status().isOk());
        save(Map.of("protocol", "SYSLOG_TCP", "endpoint", "c.example.com:514"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tlsCaPem").isEmpty());
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getTlsCaPem()).isNull();
    }

    private org.springframework.test.web.servlet.ResultActions save(Map<String, String> fields) throws Exception {
        Map<String, Object> body = new HashMap<>(fields);
        body.put("enabled", true);
        body.putIfAbsent("minSeverity", "HIGH");
        return mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)));
    }

    private org.springframework.test.web.servlet.ResultActions test(String endpoint, String ca) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/siem/test"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("protocol", "SYSLOG_TLS", "endpoint", endpoint, "tlsCaPem", ca))))
                .andExpect(status().isOk());
    }

    /** A queued event as the outbox row holds it, through the real mapper. */
    private String payload() throws Exception {
        CefEvent event = CefEvent.builder(SecurityEventType.SECURITY_SETTING_CHANGED).message("probe").build();
        return json.writeValueAsString(new SiemEvents.QueuedEvent(
                event.eventType().name(), event.timestamp().toEpochMilli(), event.message(), event.extensions(),
                event.cefSeverity()));
    }
}

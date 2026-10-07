package com.asmolabs.vectispire.common.domain.integrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.ticketing.TicketingProvider;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the integrations' registry (decision 0040)")
class IntegrationTest {

    @Test
    @DisplayName("every value of every adapter's enum is an integration, so a new one cannot be forgotten")
    void everyEnumValueIsAnIntegration() {
        List<Integration> all = Integration.all();
        Arrays.stream(ForgeKind.values()).forEach(kind -> assertThat(all).as(kind.name()).contains(Integration.of(kind)));
        Arrays.stream(SiemProtocol.values()).forEach(protocol ->
                assertThat(all).as(protocol.name()).contains(Integration.of(protocol)));
        Arrays.stream(AiProvider.values()).forEach(provider ->
                assertThat(all).as(provider.name()).contains(Integration.of(provider)));
        Arrays.stream(NotificationChannelKind.values()).forEach(channel ->
                assertThat(all).as(channel.name()).contains(Integration.of(channel)));
        Arrays.stream(TicketProvider.values()).filter(TicketProvider::isEnabled).forEach(provider ->
                assertThat(all).as(provider.name()).contains(Integration.of(provider)));
        // The issue-link providers are a second enum over the same trackers: each has its switch too.
        Arrays.stream(TicketingProvider.values()).forEach(provider -> assertThat(all).as(provider.name())
                .contains(new Integration(IntegrationFamily.TRACKER, provider.name().toLowerCase(Locale.ROOT))));
        // And nothing else: the registry is the enums, not a list kept beside them.
        assertThat(all).hasSize(ForgeKind.values().length + SiemProtocol.values().length + AiProvider.values().length
                + NotificationChannelKind.values().length + TicketProvider.values().length - 1);
    }

    @Test
    @DisplayName("the keys are the contract: family-qualified, unique across families, as the API states them")
    void keys() {
        List<String> keys = Integration.all().stream().map(Integration::key).toList();
        assertThat(keys).doesNotHaveDuplicates();
        assertThat(keys).allMatch(key -> key.matches("[a-z]+\\.[a-z0-9_]+"));
        // Frozen: renaming a key turns an integration a governor enabled into a new one that reads disabled.
        assertThat(keys).containsExactly(
                "forge.github", "forge.gitlab",
                "siem.webhook", "siem.syslog_udp", "siem.syslog_tcp", "siem.syslog_tls",
                "ai.ollama", "ai.openai",
                "notification.webhook", "notification.teams", "notification.slack", "notification.discord",
                "notification.mail",
                "tracker.gitlab", "tracker.github", "tracker.jira", "tracker.servicenow");
        // The forge and the tracker of one vendor are two switches.
        assertThat(Integration.of(ForgeKind.GITLAB)).isNotEqualTo(Integration.of(TicketProvider.GITLAB));
    }

    @Test
    @DisplayName("a key is read exactly, and no tracker is not a tracker")
    void lookups() {
        assertThat(Integration.byKey("siem.syslog_tls")).contains(Integration.of(SiemProtocol.SYSLOG_TLS));
        assertThat(Integration.byKey("SIEM.SYSLOG_TLS")).isEmpty();
        assertThat(Integration.byKey(" forge.gitlab")).isEmpty();
        assertThat(Integration.byKey("forge.bitbucket")).isEmpty();
        assertThat(Integration.byKey(null)).isEmpty();
        assertThat(Integration.all()).noneMatch(integration -> integration.name().equals("none"));
        assertThatThrownBy(() -> Integration.of(TicketProvider.NONE)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Integration(IntegrationFamily.FORGE, "Bit Bucket"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a disabled integration is a conflict typed integration-disabled, naming it as data")
    void refusal() {
        IntegrationDisabledException refused = new IntegrationDisabledException(Integration.of(AiProvider.OPENAI));
        assertThat(refused).isInstanceOf(ConflictException.class);
        assertThat(refused.conflictCause()).contains("integration-disabled");
        assertThat(refused.members()).containsExactlyEntriesOf(java.util.Map.of("integration", "ai.openai"));
        assertThat(refused.getMessage()).contains("\"ai.openai\"").contains("disabled");
    }

    @Test
    @DisplayName("an integration in use is a conflict of its own cause, integration-in-use, naming it as data and saying what uses it")
    void inUse() {
        IntegrationInUseException refused = new IntegrationInUseException(
                Integration.of(SiemProtocol.SYSLOG_TLS), "it is the transport the SIEM export sends over.");
        assertThat(refused).isInstanceOf(ConflictException.class);
        assertThat(refused.conflictCause()).contains("integration-in-use");
        assertThat(refused.members()).containsExactlyEntriesOf(java.util.Map.of("integration", "siem.syslog_tls"));
        assertThat(refused.getMessage()).isEqualTo("The integration \"siem.syslog_tls\" is in use and cannot be disabled: "
                + "it is the transport the SIEM export sends over.");
    }
}

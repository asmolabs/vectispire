package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.notifications.WebhookSignature;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.repositories.TeamWebhooks;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Signing a webhook message, from the stored secret to the header on the wire.
 *
 * <p>{@code WebhookSignatureTest} pins the scheme. What is left here is everything around it, and
 * it is where the interesting mistakes are: which secret is used, what happens when it cannot be
 * decrypted, and — the one no unit test of the scheme could see — whether the bytes signed are the
 * bytes sent.
 */
@DisplayName("signing what a scan changed")
class WebhookSigningTest {

    private static final String GLOBAL = "https://hooks.example.com/global";
    private static final String SECRET = "a-shared-secret";
    private static final String STORED = "encrypted:a-shared-secret";
    private static final Instant AT = Instant.parse("2026-08-22T10:00:00Z");

    private SettingsService settings;
    private OutboundPost post;
    private EncryptionService encryption;
    private NotificationService service;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        post = mock(OutboundPost.class);
        encryption = mock(EncryptionService.class);
        service = new NotificationService(
                settings, post, mock(TeamWebhooks.class), encryption, Clock.fixed(AT, ZoneOffset.UTC));

        when(settings.get(Setting.WEBHOOK_URL)).thenReturn(GLOBAL);
        when(settings.get(Setting.NOTIFICATION_MIN_SEVERITY)).thenReturn("high");
        when(settings.get(Setting.WEBHOOK_SIGNING_SECRET)).thenReturn(STORED);
        when(encryption.inspect(eq(STORED), anyString()))
                .thenReturn(new SecretCipher.Decrypted(SECRET, SecretCipher.SecretState.CURRENT));
    }

    @Test
    @DisplayName("the decrypted secret and the send moment reach the sender")
    void signsWithTheStoredSecret() {
        service.deliver(payload(), null);

        // The clock is passed in rather than read inside the sender, so a message's timestamp is
        // the moment Vectispire decided to send it — the same moment the signature covers.
        verify(post).postSignedJson(eq(GLOBAL), any(), any(OutboundPolicy.class), anyString(), eq(SECRET), eq(AT));
    }

    @Test
    @DisplayName("no configured secret sends unsigned rather than refusing")
    void unsignedIsAValidConfiguration() {
        when(settings.get(Setting.WEBHOOK_SIGNING_SECRET)).thenReturn("");

        service.deliver(payload(), null);

        // What every existing deployment keeps doing. Turning signing on for them would break
        // every receiver that does not verify — and there is no way to know which those are.
        verify(post).postSignedJson(eq(GLOBAL), any(), any(OutboundPolicy.class), anyString(), eq(""), eq(AT));
    }

    @Test
    @DisplayName("a secret that cannot be decrypted refuses to send, rather than sending unsigned")
    void refusesToDowngrade() {
        when(encryption.inspect(eq(STORED), anyString()))
                .thenReturn(new SecretCipher.Decrypted("", SecretCipher.SecretState.UNREADABLE));

        // **The asymmetry with the tracker token is deliberate.** An undecryptable token disables
        // ticket creation, which claims nothing. An undecryptable signing secret, treated the same
        // way, would send the message *unsigned*: a security control switching itself off after an
        // encryption-key rotation, on a deployment that configured it on purpose.
        assertThatThrownBy(() -> service.deliver(payload(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Refusing to send unsigned");
    }

    @Test
    @DisplayName("the signature covers the body that is actually written, not a second serialization")
    void signsTheBytesItSends() {
        // The one assertion that needs a real OutboundPost. A caller signing its own
        // `writeValueAsString` would sign a string the sender is free to produce differently — a
        // mapper setting, a module, a Jackson upgrade — and the result verifies nowhere while both
        // lines read correctly. It fails at the receiver, not here.
        PinnedHttpSender sender = mock(PinnedHttpSender.class);
        com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard guard =
                mock(com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard.class);
        when(sender.send(any(), any(), anyString(), any(Duration.class), anyString()))
                .thenReturn(new PinnedHttpSender.Response(200, ""));

        NotificationPayload payload = payload();
        new OutboundPost(sender, guard, new ObjectMapper())
                .postSignedJson(GLOBAL, payload, OutboundPolicy.PUBLIC_ONLY, "webhook URL", SECRET, AT);

        ArgumentCaptor<Map<String, String>> headers = ArgumentCaptor.captor();
        ArgumentCaptor<String> body = ArgumentCaptor.captor();
        verify(sender).send(any(), headers.capture(), body.capture(), any(Duration.class), anyString());

        String expected = "sha256=" + WebhookSignature.hex(SECRET, String.valueOf(AT.getEpochSecond()), body.getValue());
        assertThat(headers.getValue()).containsEntry(WebhookSignature.SIGNATURE_HEADER, expected);
        assertThat(headers.getValue())
                .containsEntry(WebhookSignature.TIMESTAMP_HEADER, String.valueOf(AT.getEpochSecond()));
    }

    private static NotificationPayload payload() {
        return NotificationPayload.of(
                new NotificationPayload.Delta("org/project", 12, List.of(), List.of(), 0, Severity.HIGH));
    }
}

package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.AiReviewService;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.NotificationService;
import com.asmolabs.vectispire.core.services.SettingsService;
import com.asmolabs.vectispire.core.services.TicketService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Saving an AI destination, and what the server refuses to take somebody's word for.
 *
 * <p>Two properties are asserted here, and neither is visible from the service alone. The first is
 * that the destination is judged against <b>the state the save will produce</b> — a request that
 * switches to OpenAI must be checked against OpenAI, not against whatever the database still says.
 * The second is that the acceptance record is written by the server: a route that took it from the
 * body would let whoever opens the public endpoint also choose whose name sits against it.
 */
@DisplayName("opening the AI endpoint to the internet")
class AiEndpointAcknowledgementTest {

    private SettingsService settings;
    private AiReviewService aiReview;
    private SettingsController controller;
    private VectispirePrincipal principal;

    @BeforeEach
    void wire() {
        settings = mock(SettingsService.class);
        aiReview = mock(AiReviewService.class);
        controller = new SettingsController(
                settings, mock(TicketService.class), mock(AuditLogService.class), aiReview,
                mock(NotificationService.class), mock(com.asmolabs.vectispire.core.repositories.Users.class));

        // Nothing configured yet: every setting reads as its stored-empty state.
        when(settings.get(any(Setting.class))).thenReturn("");
        when(aiReview.ollamaUrl()).thenReturn("http://localhost:11434");
        when(aiReview.openAiUrl()).thenReturn("https://api.openai.com/v1");

        UserEntity user = new UserEntity();
        user.setUsername("laurent");
        user.setRole(Role.ADMIN.name());
        principal = VectispirePrincipal.ofUser(user, null);
    }

    private static HttpServletRequest request() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        return request;
    }

    @Test
    @DisplayName("a public endpoint with no acceptance is refused at save time, not at scan time")
    void aPublicEndpointIsRefusedWhileTheOperatorIsStillLooking() {
        // The refusal the guard would raise, hours later, inside a scan whose report simply has no
        // review in it. Here it has to arrive on the save.
        doThrow(new UnsafeUrlException("public destination"))
                .when(aiReview).requireLocalUnlessAcknowledged(any(), anyString(), eq(false));

        assertThatThrownBy(() -> controller.update(Map.of("ai_review_provider", "openai"), principal, request()))
                .isInstanceOf(UnsafeUrlException.class);

        // And nothing was written: a refused save leaves the configuration as it was, rather than
        // half-way between two intended states.
        verify(settings, never()).set(any(Setting.class), anyString());
    }

    @Test
    @DisplayName("the destination checked is the one the save produces, not the one in the database")
    void theCheckReadsThePendingState() {
        controller.update(Map.of("ai_review_provider", "openai", "ai_review_allow_remote_url", "true"),
                principal, request());

        // Reading the stored provider here would have checked the Ollama URL — localhost — and
        // waved through a request whose whole point is to switch to OpenAI.
        verify(aiReview).requireLocalUnlessAcknowledged(
                eq(AiProvider.OPENAI), eq("https://api.openai.com/v1"), eq(true));
    }

    @Test
    @DisplayName("the acceptance is stamped by the server, with the account that made it")
    void theServerRecordsWhoAccepted() {
        controller.update(Map.of("ai_review_allow_remote_url", "true"), principal, request());

        verify(aiReview).recordRiskAcknowledgement(eq("laurent"), any());
    }

    @Test
    @DisplayName("turning it back off erases the record rather than leaving a stale acceptance")
    void turningItOffClearsTheRecord() {
        when(settings.get(Setting.AI_REVIEW_ALLOW_REMOTE)).thenReturn("true");

        controller.update(Map.of("ai_review_allow_remote_url", "false"), principal, request());

        verify(aiReview).clearRiskAcknowledgement();
    }

    @Test
    @DisplayName("saving something else while it is already on does not rewrite whose decision it was")
    void anUnrelatedSaveDoesNotRestampTheRecord() {
        when(settings.get(Setting.AI_REVIEW_ALLOW_REMOTE)).thenReturn("true");

        controller.update(Map.of("ai_review_model", "gpt-4o-mini"), principal, request());

        // Otherwise the record would name whoever edited this screen last, which is not who
        // accepted anything.
        verify(aiReview, never()).recordRiskAcknowledgement(anyString(), any());
        verify(aiReview, never()).clearRiskAcknowledgement();
    }

    @Test
    @DisplayName("the acceptance record cannot be written from the wire")
    void theRecordIsNotAcceptedFromTheBody() {
        assertThatThrownBy(() -> controller.update(
                Map.of("ai_review_risk_acknowledged_by", "somebody-else"), principal, request()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("recorded by the server");

        assertThatThrownBy(() -> controller.update(
                Map.of("ai_review_risk_acknowledged_at", "1999-01-01T00:00:00Z"), principal, request()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a public Ollama is refused too — the rule is symmetric between the providers")
    void aRemoteOllamaIsCheckedTheSameWay() {
        // The asymmetry this guards against: keying the rule on the provider name would let
        // somebody move the code off-site simply by leaving "ollama" selected and pointing its URL
        // at a host they control. The URL is what travels, so the URL is what is judged.
        controller.update(Map.of("ai_review_ollama_url", "https://ollama.example.com"), principal, request());

        verify(aiReview).requireLocalUnlessAcknowledged(
                eq(AiProvider.OLLAMA), eq("https://ollama.example.com"), eq(false));
    }

    @Test
    @DisplayName("a local endpoint needs no acceptance — the rule is the URL's, not the provider's")
    void aLocalOpenAiCompatibleEndpointIsAllowedWithoutAcknowledgement() {
        // "openai" pointed at a machine on the operator's own network sends nothing anywhere. The
        // guard is asked, and it is asked about that URL.
        controller.update(
                Map.of("ai_review_provider", "openai", "ai_review_openai_url", "http://localhost:8000/v1"),
                principal, request());

        verify(aiReview).requireLocalUnlessAcknowledged(
                eq(AiProvider.OPENAI), eq("http://localhost:8000/v1"), eq(false));
    }
}

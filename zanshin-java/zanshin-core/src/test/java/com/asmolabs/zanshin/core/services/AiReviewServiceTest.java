package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.aireview.AiReview;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.net.UnsafeUrlException;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("sending code to a local model")
class AiReviewServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private SettingsService settings;
    private OutboundJson get;
    private OutboundPost post;
    private AiReviewService service;

    @BeforeEach
    void wire() throws Exception {
        settings = mock(SettingsService.class);
        get = mock(OutboundJson.class);
        post = mock(OutboundPost.class);
        service = new AiReviewService(settings, get, post, JSON);

        when(settings.get(any())).thenReturn("");
        when(settings.isEnabled(any())).thenReturn(false);
        when(post.validate(anyString(), any(), anyString())).thenAnswer(call -> call.getArgument(0));
        when(get.get(anyString(), any(), anyString())).thenReturn(Optional.empty());
        when(post.postForResponse(anyString(), any(), any(), anyString()))
                .thenReturn("{\"message\":{\"content\":\"No issue found.\"}}");
    }

    @Test
    @DisplayName("the destination must be internal by default — this endpoint receives source code")
    void internalIsRequiredUnlessAcknowledged() {
        service.validatedUrl();

        // The opposite of the webhook's rule, and deliberately: the risk is not that the URL
        // points inward, it is that it points outward. A well-formed public URL is exactly what
        // an exfiltration channel looks like.
        verify(post).validate(anyString(), eq(OutboundPolicy.INTERNAL_REQUIRED), anyString());
    }

    @Test
    void anExplicitAcknowledgementOpensItUp() {
        when(settings.isEnabled(Setting.AI_REVIEW_ALLOW_REMOTE)).thenReturn(true);

        service.validatedUrl();

        verify(post).validate(anyString(), eq(OutboundPolicy.INTERNAL_ALLOWED), anyString());
    }

    @Test
    @DisplayName("a refused URL stops the review rather than sending the code anyway")
    void areviewAgainstARefusedUrlThrows() {
        when(post.validate(anyString(), any(), anyString())).thenThrow(new UnsafeUrlException("public destination"));

        assertThatThrownBy(() -> service.reviewCode("class A {}")).isInstanceOf(UnsafeUrlException.class);
    }

    @Test
    @DisplayName("an unreachable Ollama yields suggestions, never an empty list presented as installed")
    void modelListingFallsBack() {
        when(get.get(anyString(), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("connection refused"));

        assertThat(service.availableModels()).isEqualTo(AiReview.FALLBACK_MODEL_SUGGESTIONS);
    }

    @Test
    void listsTheModelsActuallyInstalled() throws Exception {
        when(get.get(contains("/api/tags"), any(), anyString()))
                .thenReturn(Optional.of(JSON.readTree("{\"models\":[{\"name\":\"gemma4:12b\"},{\"name\":\"qwen3:8b\"}]}")));

        assertThat(service.availableModels()).containsExactly("gemma4:12b", "qwen3:8b");
    }

    @Test
    @DisplayName("a review returns the model's answer")
    void reviewReturnsTheContent() {
        assertThat(service.reviewCode("class A {}")).isEqualTo("No issue found.");
        verify(post).postForResponse(contains("/api/chat"), any(), any(), anyString());
    }

    @Test
    @DisplayName("a review failure throws, so the caller knows it did not get one")
    void reviewFailuresAreNotSwallowed() {
        when(post.postForResponse(anyString(), any(), any(), anyString()))
                .thenThrow(new OutboundJson.OutboundFailureException("HTTP 500"));

        // The opposite contract from the configuration methods above: a caller that wanted a
        // review has to know it did not get one.
        assertThatThrownBy(() -> service.reviewCode("class A {}"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class);
    }

    @Test
    void refusesToStoreAnEmptyUrl() {
        assertThatThrownBy(() -> service.setOllamaUrl("  ")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("an unset URL falls back to the local default")
    void defaultsToLocalhost() {
        assertThat(service.ollamaUrl()).isEqualTo(AiReview.DEFAULT_OLLAMA_URL);
        assertThat(service.selectedModel()).isEqualTo(AiReview.DEFAULT_MODEL);
    }
}

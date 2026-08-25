package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

@DisplayName("LoginRateLimitFilter: in-memory Token-Bucket rate limiting on login endpoint")
class LoginRateLimitFilterTest {

    private LoginRateLimitFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private StringWriter responseWriter;

    @BeforeEach
    void setup() throws Exception {
        filter = new LoginRateLimitFilter("");
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);

        responseWriter = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    @Test
    @DisplayName("non-login requests bypass the rate limiter completely")
    void nonLoginRequestsPassThrough() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/v1/issues");
        when(request.getMethod()).thenReturn("GET");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @Test
    @DisplayName("requests within the token capacity (10 attempts) are allowed")
    void requestsWithinCapacityAreAllowed() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("192.168.1.50");

        for (int i = 0; i < 10; i++) {
            filter.doFilterInternal(request, response, chain);
        }

        verify(chain, times(10)).doFilter(request, response);
        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @Test
    @DisplayName("burst exceeding 10 requests from the same IP is blocked with HTTP 429 and Retry-After headers")
    void burstExceedingCapacityIsBlocked() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("10.0.0.99");

        // 10 allowed requests
        for (int i = 0; i < 10; i++) {
            filter.doFilterInternal(request, response, chain);
        }

        reset(chain);

        // 11th request MUST be blocked
        filter.doFilterInternal(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        verify(response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("Retry-After"), org.mockito.ArgumentMatchers.anyString());
        verify(response).setHeader(org.mockito.ArgumentMatchers.eq("X-Rate-Limit-Retry-After-Seconds"), org.mockito.ArgumentMatchers.anyString());
        assertThat(responseWriter.toString()).contains("Rate limit exceeded");
    }

    @Test
    @DisplayName("different IPs have independent token buckets")
    void differentIpsAreIndependent() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");

        // Exhaust IP 1
        when(request.getRemoteAddr()).thenReturn("1.1.1.1");
        for (int i = 0; i < 10; i++) {
            filter.doFilterInternal(request, response, chain);
        }

        reset(chain);

        // IP 2 is still fresh and allowed
        when(request.getRemoteAddr()).thenReturn("2.2.2.2");
        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("a spoofed X-Forwarded-For buys nothing when no proxy is trusted")
    void forwardedHeaderIsIgnoredWithoutATrustedProxy() throws Exception {
        // **The bypass this filter used to have.** The header was taken at face value, so an
        // attacker changed it on every request and was handed a fresh bucket each time. With no
        // trusted proxy configured the header is not evidence of anything, and the peer address
        // — which the attacker cannot choose — is what counts.
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("203.0.113.7");
        when(request.getHeader("X-Forwarded-For"))
                .thenReturn("1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8",
                        "1.2.3.9", "1.2.3.10", "1.2.3.11", "1.2.3.12", "1.2.3.13", "1.2.3.14");

        for (int i = 0; i < 10; i++) {
            filter.doFilterInternal(request, response, chain);
        }

        reset(chain);
        filter.doFilterInternal(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        verify(response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @Test
    @DisplayName("a trusted proxy's X-Forwarded-For is honoured, so its clients are counted apart")
    void forwardedHeaderIsHonouredBehindATrustedProxy() throws Exception {
        LoginRateLimitFilter behindProxy = new LoginRateLimitFilter("10.0.0.0/8");

        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        when(request.getHeader("X-Forwarded-For")).thenReturn("198.51.100.4");
        for (int i = 0; i < 10; i++) {
            behindProxy.doFilterInternal(request, response, chain);
        }

        reset(chain);

        // The same proxy, a different client behind it: its own bucket, still full.
        when(request.getHeader("X-Forwarded-For")).thenReturn("198.51.100.5");
        behindProxy.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);

        reset(chain);

        // And the exhausted one is still exhausted.
        when(request.getHeader("X-Forwarded-For")).thenReturn("198.51.100.4");
        behindProxy.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("the leftmost hop a client could have written is not the one counted")
    void onlyTheHopBehindTheTrustedChainIsTaken() throws Exception {
        LoginRateLimitFilter behindProxy = new LoginRateLimitFilter("10.0.0.0/8");

        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");

        // The client prepends a value of its own; the real address is the rightmost untrusted
        // hop, appended by the proxy. Exhausting under one forged prefix must exhaust the other.
        when(request.getHeader("X-Forwarded-For")).thenReturn("1.1.1.1, 198.51.100.9, 10.0.0.1");
        for (int i = 0; i < 10; i++) {
            behindProxy.doFilterInternal(request, response, chain);
        }

        reset(chain);

        when(request.getHeader("X-Forwarded-For")).thenReturn("9.9.9.9, 198.51.100.9, 10.0.0.1");
        behindProxy.doFilterInternal(request, response, chain);

        verify(chain, never()).doFilter(request, response);
    }

    @Test
    @DisplayName("the MFA verification route is limited too, not just the password one")
    void mfaVerificationIsLimited() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/v1/auth/mfa/verify");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRemoteAddr()).thenReturn("192.0.2.10");

        for (int i = 0; i < 10; i++) {
            filter.doFilterInternal(request, response, chain);
        }

        reset(chain);
        filter.doFilterInternal(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        verify(response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }
}

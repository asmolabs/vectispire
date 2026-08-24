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
        filter = new LoginRateLimitFilter();
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
}

package com.asmolabs.vectispire.core.api.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

@DisplayName("The ceiling on refused bearer tokens")
class BearerRateLimitFilterTest {

    private static final int CAPACITY = 3;

    private BearerRateLimitFilter filter;
    private AuditLogService audit;
    private HttpServletResponse response;
    private StringWriter written;

    @BeforeEach
    void setUp() throws Exception {
        audit = mock(AuditLogService.class);
        filter = new BearerRateLimitFilter(new TrustedProxies(""), audit, CAPACITY, Duration.ofMinutes(5));

        response = mock(HttpServletResponse.class);
        written = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(written));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static HttpServletRequest credentialed(String peer) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(peer);
        when(request.getHeader("Authorization")).thenReturn("Bearer zsk-whatever");
        when(request.getRequestURI()).thenReturn("/api/v1/issues");
        return request;
    }

    /** The chain leaves nothing in the context, which is what a refused token looks like. */
    private static FilterChain refusing() {
        return mock(FilterChain.class);
    }

    private static FilterChain accepting() {
        return (request, response) -> SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken("someone", null));
    }

    @Test
    @DisplayName("refuses an address once it has spent its allowance")
    void refusesAfterCapacity() throws Exception {
        HttpServletRequest request = credentialed("203.0.113.9");

        for (int attempt = 0; attempt < CAPACITY; attempt++) {
            FilterChain chain = refusing();
            filter.doFilterInternal(request, response, chain);
            verify(chain).doFilter(request, response);
        }

        FilterChain blocked = refusing();
        filter.doFilterInternal(request, response, blocked);

        verify(blocked, never()).doFilter(any(), any());
        verify(response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        assertThat(written.toString()).contains("Too many refused credentials");
    }

    /**
     * The property that keeps this filter off the population it is not aimed at.
     *
     * <p>A remote agent long-polls every thirty seconds with a key that works; an interface makes
     * twenty calls to paint one page. Counting those would throttle the deployment rather than
     * the sweep.
     */
    @Test
    @DisplayName("never counts a token that worked")
    void successNeverCounts() throws Exception {
        HttpServletRequest request = credentialed("203.0.113.9");

        for (int attempt = 0; attempt < CAPACITY * 5; attempt++) {
            filter.doFilterInternal(request, response, accepting());
            SecurityContextHolder.clearContext();
        }

        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @Test
    @DisplayName("never counts a request that carried no credentials at all")
    void anonymousNeverCounts() throws Exception {
        HttpServletRequest anonymous = mock(HttpServletRequest.class);
        when(anonymous.getRemoteAddr()).thenReturn("203.0.113.9");
        when(anonymous.getHeader("Authorization")).thenReturn(null);

        for (int attempt = 0; attempt < CAPACITY * 5; attempt++) {
            FilterChain chain = refusing();
            filter.doFilterInternal(anonymous, response, chain);
            verify(chain).doFilter(anonymous, response);
        }

        verify(response, never()).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
    }

    @Test
    @DisplayName("counts per address: one exhausted client does not refuse another")
    void perAddress() throws Exception {
        HttpServletRequest noisy = credentialed("203.0.113.9");
        for (int attempt = 0; attempt <= CAPACITY; attempt++) {
            filter.doFilterInternal(noisy, response, refusing());
        }

        FilterChain other = refusing();
        HttpServletRequest quiet = credentialed("198.51.100.7");
        filter.doFilterInternal(quiet, response, other);

        verify(other).doFilter(quiet, response);
    }

    /**
     * One entry per window, not one per retry.
     *
     * <p>A loop retrying every second would otherwise write a thousand identical rows into a log
     * that is never purged, and bury the entry that mattered inside its own alarm.
     */
    @Test
    @DisplayName("writes one audit entry when the allowance runs out, and not one per refusal")
    void auditsOnce() throws Exception {
        HttpServletRequest request = credentialed("203.0.113.9");

        for (int attempt = 0; attempt < CAPACITY + 10; attempt++) {
            filter.doFilterInternal(request, response, refusing());
        }

        verify(audit, times(1)).record(any());
    }

    @Test
    @DisplayName("reset clears the tracked addresses")
    void resetClears() throws Exception {
        HttpServletRequest request = credentialed("203.0.113.9");
        for (int attempt = 0; attempt <= CAPACITY; attempt++) {
            filter.doFilterInternal(request, response, refusing());
        }

        filter.reset();

        FilterChain afterReset = refusing();
        filter.doFilterInternal(request, response, afterReset);
        verify(afterReset).doFilter(request, response);
    }
}

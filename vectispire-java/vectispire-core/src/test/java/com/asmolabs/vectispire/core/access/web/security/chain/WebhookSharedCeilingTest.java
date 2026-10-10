package com.asmolabs.vectispire.core.access.web.security.chain;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.RateWindows;
import com.asmolabs.vectispire.core.access.web.security.TrustedProxies;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * The tracker webhook's ceiling holds for the deployment, not for each instance.
 *
 * <p>Two filters built on the one database stand for two instances behind a load balancer: each has
 * its own in-memory buckets, as each instance does, and they share {@link RateWindows}. Before the
 * shared count, deliveries alternating between them met a ceiling of three on each — six in all —
 * and the configured figure was a property of how many instances there happened to be.
 */
@DisplayName("the tracker webhook's ceiling, across instances")
class WebhookSharedCeilingTest extends VectispireContextTest {

    private static final int CEILING = 3;

    @Autowired
    private TrustedProxies proxies;

    @Autowired
    private RateWindows windows;

    @BeforeEach
    void forgetTheCounts() {
        windows.forget(RateWindows.Limit.TICKET_WEBHOOK);
    }

    @Test
    @DisplayName("deliveries alternating between two instances meet one ceiling, and are told when to retry")
    void twoInstancesShareOneCeiling() throws Exception {
        WebhookRateLimitFilter first = instance();
        WebhookRateLimitFilter second = instance();
        String address = "198.51.100.17";

        List<Integer> statuses = new ArrayList<>();
        for (int delivery = 0; delivery < 6; delivery++) {
            statuses.add(deliver(delivery % 2 == 0 ? first : second, address).getStatus());
        }

        // Each instance has seen three at most, so its own bucket admits every one of them.
        assertThat(statuses).containsExactly(200, 200, 200, 429, 429, 429);
        MockHttpServletResponse refused = deliver(first, address);
        assertThat(refused.getHeader("Retry-After")).isNotNull();
        assertThat(Long.parseLong(refused.getHeader("Retry-After"))).isBetween(1L, 3600L);
    }

    @Test
    @DisplayName("another address has an allowance of its own")
    void addressesAreCountedApart() throws Exception {
        WebhookRateLimitFilter first = instance();
        WebhookRateLimitFilter second = instance();
        for (int delivery = 0; delivery < CEILING; delivery++) {
            assertThat(deliver(delivery % 2 == 0 ? first : second, "198.51.100.18").getStatus()).isEqualTo(200);
        }

        assertThat(deliver(second, "198.51.100.19").getStatus()).isEqualTo(200);
        assertThat(deliver(first, "198.51.100.18").getStatus()).isEqualTo(429);
    }

    @Test
    @DisplayName("an IPv6 tracker rotating addresses within its /64 meets one ceiling, and the next /64 has its own")
    void oneSlash64IsOneAllowance() throws Exception {
        WebhookRateLimitFilter first = instance();
        WebhookRateLimitFilter second = instance();
        for (int delivery = 1; delivery <= CEILING; delivery++) {
            WebhookRateLimitFilter instance = delivery % 2 == 0 ? first : second;
            assertThat(deliver(instance, "2001:db8:5:6::" + delivery).getStatus()).isEqualTo(200);
        }

        // Fresh to this instance's own buckets as an address, the same client as a /64.
        assertThat(deliver(first, "2001:db8:5:6:dead:beef:0:1").getStatus()).isEqualTo(429);
        assertThat(deliver(first, "2001:db8:5:7::1").getStatus()).isEqualTo(200);
    }

    private WebhookRateLimitFilter instance() {
        // An hour rather than the shipped minute: a test crossing a window's boundary starts over.
        return new WebhookRateLimitFilter(proxies, windows, CEILING, Duration.ofHours(1));
    }

    private static MockHttpServletResponse deliver(WebhookRateLimitFilter filter, String address) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", WebhookRateLimitFilter.WEBHOOK_PREFIX + "jira");
        request.setRemoteAddr(address);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }
}

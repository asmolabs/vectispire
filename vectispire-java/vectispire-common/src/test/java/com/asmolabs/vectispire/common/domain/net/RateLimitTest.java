package com.asmolabs.vectispire.common.domain.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("reading a rate limit")
class RateLimitTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    private static Function<String, Optional<String>> headers(String... pairs) {
        Map<String, String> map = new java.util.HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put(pairs[i], pairs[i + 1]);
        }
        return name -> Optional.ofNullable(map.get(name));
    }

    @Test
    @DisplayName("429 is a limit; a 403 only with the limit's headers — otherwise it is a refusal")
    void whatIsALimit() {
        assertThat(RateLimit.limited(429, headers())).isTrue();
        assertThat(RateLimit.limited(403, headers("x-ratelimit-remaining", "0"))).isTrue();
        assertThat(RateLimit.limited(403, headers("ratelimit-remaining", " 0 "))).isTrue();
        assertThat(RateLimit.limited(403, headers("retry-after", "30"))).isTrue();
        assertThat(RateLimit.limited(403, headers("x-ratelimit-remaining", "12"))).isFalse();
        assertThat(RateLimit.limited(403, headers())).isFalse();
        assertThat(RateLimit.limited(401, headers("retry-after", "30"))).isFalse();
        assertThat(RateLimit.limited(200, headers("x-ratelimit-remaining", "0"))).isFalse();
    }

    @Test
    @DisplayName("Retry-After first, in seconds or as a date")
    void retryAfter() {
        assertThat(RateLimit.waitOf(headers("retry-after", "17", "x-ratelimit-reset",
                String.valueOf(NOW.getEpochSecond() + 500)), NOW)).contains(Duration.ofSeconds(17));
        assertThat(RateLimit.waitOf(headers("retry-after", "Sat, 03 Oct 2026 12:01:30 GMT"), NOW))
                .contains(Duration.ofSeconds(90));
    }

    @Test
    @DisplayName("GitHub's X-RateLimit-Reset and GitLab's RateLimit-Reset are instants; a small RateLimit-Reset is a delay")
    void resets() {
        assertThat(RateLimit.waitOf(headers("x-ratelimit-reset", String.valueOf(NOW.getEpochSecond() + 45)), NOW))
                .contains(Duration.ofSeconds(45));
        assertThat(RateLimit.waitOf(headers("ratelimit-reset", String.valueOf(NOW.getEpochSecond() + 3600)), NOW))
                .contains(Duration.ofHours(1));
        assertThat(RateLimit.waitOf(headers("ratelimit-reset", "20"), NOW)).contains(Duration.ofSeconds(20));
    }

    @Test
    @DisplayName("a reset already past waits nothing; no readable header is no wait known")
    void unknown() {
        assertThat(RateLimit.waitOf(headers("x-ratelimit-reset", String.valueOf(NOW.getEpochSecond() - 10)), NOW))
                .contains(Duration.ZERO);
        assertThat(RateLimit.waitOf(headers("retry-after", "soon"), NOW)).isEmpty();
        assertThat(RateLimit.waitOf(headers(), NOW)).isEmpty();
    }
}

package com.asmolabs.vectispire.core.outbound;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The paged call (decision 0037 §3, lot D2) against forges answering over HTTPS from loopback behind a private
 * CA — a GitLab and a GitHub as each pages and limits — through the real door: what is pinned is what reached
 * the wire, which request was never sent, and how long the listing slept. The sleeper moves a clock instead of
 * sleeping, so a sixty-second wait costs nothing and is still measured. Bounded: a pager that stopped honouring
 * its deadline would otherwise wait on a rate limit forever, and so would the build.
 */
@Timeout(60)
@DisplayName("a listing read page by page")
class OutboundPagerTest {

    private static final String TOKEN = "glpat-Pager00000000000000000"; // gitleaks:allow
    private static final Instant START = Instant.parse("2026-10-03T12:00:00Z");

    private ForgeStub forge;
    private ForgeStub elsewhere;
    private OutboundJson outbound;
    private MovingClock clock;
    private final List<Duration> slept = new ArrayList<>();

    @BeforeEach
    void start() throws Exception {
        forge = ForgeStub.start();
        elsewhere = ForgeStub.start();
        outbound = new OutboundJson(new PinnedHttpSender(), new OutboundUrlGuard(), new ObjectMapper());
        clock = new MovingClock(START);
    }

    @AfterEach
    void stop() {
        forge.close();
        elsewhere.close();
    }

    private OutboundPager pager(ForgeStub server, Duration maxWait, Duration timeout, Instant deadline) {
        PinnedCa ca = PinnedCa.parse(server.caPem, Instant.now(), new PinnedCa.Subject("The forge's CA", "the forge"));
        return outbound.pager(new OutboundPager.Settings(server.baseUrl() + "/api/v4", OutboundPolicy.INTERNAL_ALLOWED,
                "GitLab at " + server.baseUrl(), Map.of("PRIVATE-TOKEN", TOKEN), Optional.of(ca), deadline, maxWait,
                timeout, null), clock, duration -> {
                    slept.add(duration);
                    clock.advance(duration);
                });
    }

    private OutboundPager pager() {
        return pager(forge, Duration.ofSeconds(60), OutboundJson.TIMEOUT, START.plus(Duration.ofMinutes(30)));
    }

    /** Follows every next page from {@code first}; the paths read, in order. */
    private List<String> walk(OutboundPager pager, String first, OutboundPager.NextPage nextPage) {
        List<String> pages = new ArrayList<>();
        Optional<String> url = Optional.of(first);
        while (url.isPresent()) {
            OutboundJson.Answer answer = pager.get(url.get());
            pages.add(answer.body().orElseThrow().path("page").asText());
            url = pager.next(answer, url.get(), nextPage);
        }
        return pages;
    }

    @Test
    @DisplayName("GitLab's keyset Link is followed to the last page, the token on every request")
    void gitlabKeyset() {
        String first = "/api/v4/projects?membership=true&pagination=keyset&order_by=id&sort=asc&per_page=100";
        String second = "/api/v4/projects?id_after=100&membership=true&pagination=keyset&order_by=id&sort=asc&per_page=100";
        forge.route(first, Reply.json("{\"page\":\"1\"}").with("Link", "<" + forge.baseUrl() + second + ">; rel=\"next\""));
        forge.route(second, Reply.json("{\"page\":\"2\"}"));

        OutboundPager pager = pager();
        assertThat(walk(pager, forge.baseUrl() + first, OutboundPager.NextPage.GITLAB)).containsExactly("1", "2");

        assertThat(pager.requests()).isEqualTo(2);
        assertThat(forge.seen).allSatisfy(seen -> assertThat(seen.headers()).containsEntry("private-token", TOKEN));
    }

    @Test
    @DisplayName("GitLab's offset listing without a Link: X-Next-Page sets the page, the rest of the query kept")
    void gitlabOffset() {
        forge.route("/api/v4/groups?min_access_level=10&per_page=100",
                Reply.json("{\"page\":\"1\"}").with("X-Next-Page", "2"));
        forge.route("/api/v4/groups?min_access_level=10&per_page=100&page=2",
                Reply.json("{\"page\":\"2\"}").with("X-Next-Page", "3"));
        forge.route("/api/v4/groups?min_access_level=10&per_page=100&page=3",
                Reply.json("{\"page\":\"3\"}").with("X-Next-Page", ""));

        assertThat(walk(pager(), forge.baseUrl() + "/api/v4/groups?min_access_level=10&per_page=100",
                OutboundPager.NextPage.GITLAB)).containsExactly("1", "2", "3");
    }

    @Test
    @DisplayName("GitHub's relative Link is resolved against the page that named it")
    void githubRelativeLink() {
        forge.route("/api/v4/orgs/acme/repos?per_page=100",
                Reply.json("{\"page\":\"1\"}").with("Link", "</api/v4/orgs/acme/repos?per_page=100&page=2>; rel=\"next\""));
        forge.route("/api/v4/orgs/acme/repos?per_page=100&page=2", Reply.json("{\"page\":\"2\"}"));

        assertThat(walk(pager(), forge.baseUrl() + "/api/v4/orgs/acme/repos?per_page=100", OutboundPager.NextPage.LINK))
                .containsExactly("1", "2");
    }

    @Test
    @DisplayName("a next page on another port of the same host is refused before anything is sent there")
    void anotherPortIsAnotherOrigin() {
        forge.route("/api/v4/projects", Reply.json("{\"page\":\"1\"}")
                .with("Link", "<" + elsewhere.baseUrl() + "/api/v4/projects?page=2>; rel=\"next\""));
        elsewhere.route("/api/v4/projects?page=2", Reply.json("{\"page\":\"2\"}"));

        assertThatThrownBy(() -> walk(pager(), forge.baseUrl() + "/api/v4/projects", OutboundPager.NextPage.LINK))
                .isInstanceOf(OutboundPager.CrossOriginPageException.class)
                .hasMessageContaining("nothing was sent there")
                .hasMessageNotContaining("page=2");
        assertThat(elsewhere.seen).isEmpty();
    }

    @Test
    @DisplayName("nor over http on the same host and port, nor to another host name")
    void otherSchemesAndHosts() {
        OutboundPager pager = pager();
        String port = forge.baseUrl().substring(forge.baseUrl().lastIndexOf(':'));

        assertThatThrownBy(() -> pager.get("http://127.0.0.1" + port + "/api/v4/projects"))
                .isInstanceOf(OutboundPager.CrossOriginPageException.class);
        assertThatThrownBy(() -> pager.get("https://localhost" + port + "/api/v4/projects"))
                .isInstanceOf(OutboundPager.CrossOriginPageException.class);
        assertThatThrownBy(() -> pager.get("https://evil.example@127.0.0.1" + port + "/api/v4/projects"))
                .isInstanceOf(OutboundPager.CrossOriginPageException.class);
        assertThat(forge.seen).isEmpty();
        assertThat(pager.requests()).isZero();
    }

    @Test
    @DisplayName("GitLab's 429 with Retry-After is waited out inside the listing, and the page read")
    void retryAfterWaited() {
        forge.sequence("/api/v4/projects", Reply.status(429).with("Retry-After", "7")
                .with("RateLimit-Reset", String.valueOf(START.getEpochSecond() + 50)));
        forge.route("/api/v4/projects", Reply.json("{\"page\":\"1\"}"));

        OutboundPager pager = pager();
        assertThat(pager.get(forge.baseUrl() + "/api/v4/projects").status()).isEqualTo(200);

        assertThat(slept).containsExactly(Duration.ofSeconds(7));
        assertThat(pager.rateLimitWaited()).isEqualTo(Duration.ofSeconds(7));
        assertThat(pager.requests()).isEqualTo(2);
    }

    @Test
    @DisplayName("GitHub's spent primary limit, a 403 with X-RateLimit-Remaining 0, waits until its reset")
    void githubPrimaryLimit() {
        forge.sequence("/api/v4/orgs/acme/repos", Reply.status(403).with("X-RateLimit-Remaining", "0")
                .with("X-RateLimit-Reset", String.valueOf(START.getEpochSecond() + 42)));
        forge.route("/api/v4/orgs/acme/repos", Reply.json("{\"page\":\"1\"}"));

        assertThat(pager().get(forge.baseUrl() + "/api/v4/orgs/acme/repos").status()).isEqualTo(200);
        assertThat(slept).containsExactly(Duration.ofSeconds(42));
    }

    @Test
    @DisplayName("a 403 without the limit's headers is the caller's to read, not a wait")
    void aRefusalIsNotALimit() {
        forge.route("/api/v4/groups/7/projects", Reply.status(403));

        assertThat(pager().get(forge.baseUrl() + "/api/v4/groups/7/projects").status()).isEqualTo(403);
        assertThat(slept).isEmpty();
    }

    @Test
    @DisplayName("a wait longer than the bound is not slept: it says when the limit lifts")
    void aLongWaitEndsTheListing() {
        forge.route("/api/v4/projects", Reply.status(429).with("RateLimit-Reset",
                String.valueOf(START.getEpochSecond() + 3600)));

        assertThatThrownBy(() -> pager().get(forge.baseUrl() + "/api/v4/projects"))
                .isInstanceOfSatisfying(OutboundPager.RateLimitedException.class,
                        limited -> assertThat(limited.liftsAt()).isEqualTo(START.plusSeconds(3600)));
        assertThat(slept).isEmpty();
        assertThat(forge.count("/api/v4/projects")).isOne();
    }

    @Test
    @DisplayName("a wait within the bound that would cross the deadline is not slept either")
    void aWaitPastTheDeadline() {
        forge.route("/api/v4/projects", Reply.status(429).with("Retry-After", "30"));

        assertThatThrownBy(() -> pager(forge, Duration.ofSeconds(60), OutboundJson.TIMEOUT, START.plusSeconds(20))
                        .get(forge.baseUrl() + "/api/v4/projects"))
                .isInstanceOf(OutboundPager.DeadlineReachedException.class);
        assertThat(slept).isEmpty();
    }

    @Test
    @DisplayName("no request is sent past the deadline")
    void nothingPastTheDeadline() {
        forge.route("/api/v4/projects", Reply.json("{}"));

        assertThatThrownBy(() -> pager(forge, Duration.ofSeconds(60), OutboundJson.TIMEOUT, START)
                        .get(forge.baseUrl() + "/api/v4/projects"))
                .isInstanceOf(OutboundPager.DeadlineReachedException.class);
        assertThat(forge.seen).isEmpty();
    }

    @Test
    @DisplayName("a 5xx is retried with back-off — one, two seconds — and the page read when the server recovers")
    void serverErrorsRetried() {
        forge.sequence("/api/v4/projects", Reply.status(502), Reply.status(503));
        forge.route("/api/v4/projects", Reply.json("{\"page\":\"1\"}"));

        OutboundPager pager = pager();
        assertThat(pager.get(forge.baseUrl() + "/api/v4/projects").status()).isEqualTo(200);
        assertThat(slept).containsExactly(Duration.ofSeconds(1), Duration.ofSeconds(2));
        assertThat(pager.rateLimitWaited()).as("a back-off is not a rate limit").isZero();
    }

    @Test
    @DisplayName("three retries, then the page fails")
    void serverErrorsGiveUp() {
        forge.route("/api/v4/projects", Reply.status(500));

        OutboundPager pager = pager();
        assertThatThrownBy(() -> pager.get(forge.baseUrl() + "/api/v4/projects"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class)
                .hasMessageContaining("HTTP 500");
        assertThat(pager.requests()).isEqualTo(4);
        assertThat(slept).containsExactly(Duration.ofSeconds(1), Duration.ofSeconds(2), Duration.ofSeconds(4));
    }

    @Test
    @DisplayName("a server that does not answer in time is retried like one that fails, then the page fails")
    void timeouts() {
        forge.route("/api/v4/projects", Reply.json("{}"));
        forge.slow("/api/v4/projects", Duration.ofSeconds(3));

        OutboundPager pager = pager(forge, Duration.ofSeconds(60), Duration.ofMillis(300), START.plusSeconds(1800));
        assertThatThrownBy(() -> pager.get(forge.baseUrl() + "/api/v4/projects"))
                .isInstanceOf(OutboundJson.OutboundFailureException.class);
        assertThat(pager.requests()).isEqualTo(4);
    }

    @Test
    @DisplayName("the hook runs before every request, retries and waits included — where a run renews its lease")
    void beforeEachRequest() {
        forge.sequence("/api/v4/projects", Reply.status(429).with("Retry-After", "1"), Reply.status(500));
        forge.route("/api/v4/projects", Reply.json("{}"));
        int[] calls = {0};
        PinnedCa ca = PinnedCa.parse(forge.caPem, Instant.now(), new PinnedCa.Subject("The forge's CA", "the forge"));
        OutboundPager pager = outbound.pager(new OutboundPager.Settings(forge.baseUrl(), OutboundPolicy.INTERNAL_ALLOWED,
                "GitLab", Map.of(), Optional.of(ca), START.plusSeconds(600), Duration.ofSeconds(60),
                OutboundJson.TIMEOUT, () -> calls[0]++), clock, clock::advance);

        pager.get(forge.baseUrl() + "/api/v4/projects");
        assertThat(calls[0]).isEqualTo(3);
    }

    /** A clock the sleeper moves. */
    static final class MovingClock extends Clock {

        private Instant now;

        MovingClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Test
    @DisplayName("a pager's settings print the credential's header names, never its token")
    void settingsWithholdTheCredential() {
        // An invented value: the point is that it does not appear.
        var settings = new OutboundPager.Settings("https://gitlab.example.org/api/v4", OutboundPolicy.PUBLIC_ONLY,
                "forge", Map.of("PRIVATE-TOKEN", "invented-token-value"), Optional.empty(), Instant.EPOCH,
                Duration.ofSeconds(1), Duration.ofSeconds(1), null);

        assertThat(settings.toString()).contains("PRIVATE-TOKEN", "gitlab.example.org")
                .doesNotContain("invented-token-value");
    }
}

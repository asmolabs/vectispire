package com.asmolabs.vectispire.core.forges.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.ForgeAddress;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * GitHub's listing (decision 0037 §3, lot D4) against recorded answers, for the two clouds whose hosts a test cannot
 * stand up: github.com and a data-residency {@code <sub>.ghe.com}. The door is the real one — {@link OutboundJson},
 * the pager, the guard applying {@code PUBLIC_ONLY} to the names resolved to a public address — and only the
 * exchange is recorded: what is pinned is the URL each request went to, the headers it carried, and what the listing
 * was told. Enterprise Server, at {@code /api/v3} on the internal network, is the HTTP suite's
 * ({@code ForgeGitHubRoutesTest}), against a stub on loopback.
 */
@DisplayName("GitHub's listing")
class GitHubListerTest {

    private static final String TOKEN = "github_pat_11LISTER000000000000000_lister"; // gitleaks:allow
    private static final Instant START = Instant.parse("2026-10-03T12:00:00Z");
    private static final String API = "https://api.github.com";

    private Recorded forge;
    private MovingClock clock;
    private final List<Duration> slept = new ArrayList<>();

    @BeforeEach
    void start() {
        forge = new Recorded();
        clock = new MovingClock(START);
    }

    // ---- The forge's answers.

    static String repository(long id, String fullName, String visibility, boolean fork, boolean archived) {
        String owner = fullName.substring(0, fullName.indexOf('/'));
        String name = fullName.substring(fullName.indexOf('/') + 1);
        return "{\"id\":" + id + ",\"node_id\":\"R_x\",\"name\":\"" + name + "\",\"full_name\":\"" + fullName + "\","
                + "\"owner\":{\"login\":\"" + owner + "\",\"type\":\"Organization\"},\"private\":"
                + !"public".equals(visibility) + ",\"visibility\":\"" + visibility + "\",\"fork\":" + fork
                + ",\"archived\":" + archived + ",\"default_branch\":\"main\",\"pushed_at\":\"2026-09-30T08:15:00Z\","
                + "\"language\":\"Kotlin\",\"size\":2,\"clone_url\":\"https://github.com/" + fullName + ".git\","
                + "\"ssh_url\":\"git@github.com:" + fullName + ".git\",\"html_url\":\"https://github.com/" + fullName + "\"}";
    }

    private static PinnedHttpSender.Response json(String body, String... headers) {
        Map<String, List<String>> all = new HashMap<>();
        for (int i = 0; i < headers.length; i += 2) {
            all.put(headers[i].toLowerCase(java.util.Locale.ROOT), List.of(headers[i + 1]));
        }
        return new PinnedHttpSender.Response(200, body, all);
    }

    private static PinnedHttpSender.Response status(int status, String... headers) {
        Map<String, List<String>> all = new HashMap<>();
        for (int i = 0; i < headers.length; i += 2) {
            all.put(headers[i].toLowerCase(java.util.Locale.ROOT), List.of(headers[i + 1]));
        }
        return new PinnedHttpSender.Response(status, "{\"message\":\"" + status + "\"}", all);
    }

    /** A fine-grained token's {@code /user}: no {@code X-OAuth-Scopes}. */
    private static PinnedHttpSender.Response user(String login) {
        return json("{\"login\":\"" + login + "\",\"id\":7,\"type\":\"User\"}");
    }

    /** A classic token's {@code /user}: GitHub states its scopes. */
    private static PinnedHttpSender.Response classicUser(String login) {
        return json("{\"login\":\"" + login + "\",\"id\":7,\"type\":\"User\"}", "X-OAuth-Scopes", "repo, read:org");
    }

    private static String orgRepos(String api, String org) {
        return api + "/orgs/" + org + "/repos?type=all&sort=full_name&per_page=100";
    }

    // ---- The listing.

    private Listed list(String typed, String owner) {
        ForgeAddress address = ForgeAddress.of(ForgeKind.GITHUB, typed);
        Listed listed = new Listed(new ForgeClient.Target(address, owner, OutboundPolicy.PUBLIC_ONLY, Optional.empty()));
        new GitHubLister().list(listed);
        return listed;
    }

    @Test
    @DisplayName("github.com, a fine-grained token for an organisation: that organisation alone, every page, every field")
    void aFineGrainedTokenListsItsOwner() {
        forge.on(API + "/user", user("ada"));
        forge.on(orgRepos(API, "acme"), json("[" + repository(101, "acme/api", "private", false, false) + ","
                + repository(102, "acme/portal", "internal", true, true) + "]",
                "Link", "<" + API + "/organizations/9/repos?type=all&sort=full_name&per_page=100&page=2>; rel=\"next\", "
                        + "<" + API + "/organizations/9/repos?type=all&sort=full_name&per_page=100&page=2>; rel=\"last\""));
        forge.on(API + "/organizations/9/repos?type=all&sort=full_name&per_page=100&page=2",
                json("[" + repository(103, "acme/docs", "public", false, false) + "]"));

        Listed listed = list("", "acme");

        assertThat(forge.urls()).as("no /user/orgs and no /user/repos: a fine-grained token has one resource owner")
                .containsExactly(API + "/user", orgRepos(API, "acme"),
                        API + "/organizations/9/repos?type=all&sort=full_name&per_page=100&page=2");
        assertThat(forge.seen).allSatisfy(request -> {
            assertThat(request.headers()).containsEntry("Authorization", "Bearer " + TOKEN)
                    .containsEntry("X-GitHub-Api-Version", "2022-11-28");
            assertThat(request.addresses()).as("the cloud is reached under PUBLIC_ONLY, at the address checked")
                    .containsExactly("140.82.112.6");
        });
        assertThat(listed.namespaces).containsExactly("acme");
        assertThat(listed.repositories).extracting(DiscoveredRepository::forgeId).containsExactly("101", "102", "103");
        DiscoveredRepository api = listed.repositories.getFirst();
        assertThat(api.fullPath()).isEqualTo("acme/api");
        assertThat(api.namespacePath()).isEqualTo("acme");
        assertThat(api.name()).isEqualTo("api");
        assertThat(api.personal()).isFalse();
        assertThat(api.defaultBranch()).isEqualTo("main");
        assertThat(api.archived()).isFalse();
        assertThat(api.fork()).as("GitHub always states it: not unknown").isFalse();
        assertThat(api.visibility()).isEqualTo("private");
        assertThat(api.lastActivityAt()).as("pushed_at").isEqualTo(Instant.parse("2026-09-30T08:15:00Z"));
        assertThat(api.language()).isEqualTo("Kotlin");
        assertThat(api.sizeBytes()).as("GitHub states kibibytes").isEqualTo(2048);
        assertThat(api.httpUrl()).isEqualTo("https://github.com/acme/api.git");
        assertThat(api.sshUrl()).isEqualTo("git@github.com:acme/api.git");
        assertThat(api.webUrl()).isEqualTo("https://github.com/acme/api");
        DiscoveredRepository portal = listed.repositories.get(1);
        assertThat(portal.visibility()).as("an enterprise's internal repository").isEqualTo("internal");
        assertThat(portal.fork()).isTrue();
        assertThat(portal.archived()).isTrue();
        assertThat(listed.unreadable).isEmpty();
        assertThat(listed.incomplete).isEmpty();
    }

    @Test
    @DisplayName("data residency: the API at api.<subdomain>.ghe.com; a token for the user lists its own repositories, flagged personal")
    void dataResidencyAndThePersonalNamespace() {
        String api = "https://api.acme.ghe.com";
        forge.on(api + "/user", user("ada_acme"));
        forge.on(api + GitHubLister.USER_REPOS, json("[" + repository(201, "ada_acme/sandbox", "private", false, false)
                .replace("github.com", "acme.ghe.com") + "]"));

        Listed listed = list("https://acme.ghe.com", "ADA_acme");

        assertThat(forge.urls()).containsExactly(api + "/user", api + GitHubLister.USER_REPOS);
        assertThat(listed.namespaces).containsExactly("ada_acme");
        assertThat(listed.repositories).singleElement().satisfies(repository -> {
            assertThat(repository.personal()).as("offered unticked by the selection").isTrue();
            assertThat(repository.namespacePath()).isEqualTo("ada_acme");
            assertThat(repository.httpUrl()).isEqualTo("https://acme.ghe.com/ada_acme/sandbox.git");
        });
    }

    @Test
    @DisplayName("a classic token: the owner, every organisation it sees, its user's own — and one it cannot read is marked, not fatal")
    void aClassicTokenAndThePerOrganisationRefusal() {
        forge.on(API + "/user", classicUser("ada"));
        forge.on(API + GitHubLister.USER_ORGS, json("[{\"login\":\"Acme\"},{\"login\":\"secure\"},{\"login\":\"walled\"},"
                + "{\"login\":\"gone\"},{\"login\":\"globex\"}]"));
        forge.on(orgRepos(API, "acme"), json("[" + repository(101, "acme/api", "private", false, false) + "]"));
        forge.on(orgRepos(API, "secure"), status(403, "X-GitHub-SSO",
                "required; url=https://github.com/orgs/secure/sso?authorization_request=AZ0"));
        forge.on(orgRepos(API, "walled"), status(403, "X-RateLimit-Remaining", "4990"));
        forge.on(orgRepos(API, "gone"), status(404));
        forge.on(orgRepos(API, "globex"), json("[" + repository(301, "globex/core", "private", false, false) + "]"));
        forge.on(API + GitHubLister.USER_REPOS, json("[" + repository(401, "ada/dotfiles", "public", false, false) + "]"));

        Listed listed = list("", "acme");

        assertThat(forge.urls()).as("the owner first, once whatever its case; the rest in GitHub's order").containsExactly(
                API + "/user", API + GitHubLister.USER_ORGS, orgRepos(API, "acme"), orgRepos(API, "secure"),
                orgRepos(API, "walled"), orgRepos(API, "gone"), orgRepos(API, "globex"), API + GitHubLister.USER_REPOS);
        assertThat(listed.repositories).extracting(DiscoveredRepository::forgeId).containsExactly("101", "301", "401");
        assertThat(listed.repositories.getLast().personal()).isTrue();
        assertThat(listed.namespaces).containsExactly("acme", "secure", "walled", "gone", "globex", "ada");
        assertThat(listed.unreadable.keySet()).containsExactly("secure", "walled", "gone");
        assertThat(listed.unreadable.get("secure")).contains("SAML single sign-on").contains("authorise the token")
                .doesNotContain("authorization_request");
        assertThat(listed.unreadable.get("walled")).contains("HTTP 403").contains("IP allow list");
        assertThat(listed.unreadable.get("gone")).contains("HTTP 404");
        assertThat(listed.incomplete).isEmpty();
    }

    @Test
    @DisplayName("what GitHub withholds unnamed — single sign-on filtering the organisations, read:org missing — is said, not guessed")
    void withheldOrganisations() {
        forge.on(API + "/user", classicUser("ada"));
        forge.on(API + GitHubLister.USER_ORGS, json("[{\"login\":\"acme\"}]",
                "X-GitHub-SSO", "partial-results; organizations=21955855,20582480"));
        forge.on(orgRepos(API, "acme"), json("[]"));
        forge.on(API + GitHubLister.USER_REPOS, json("[]"));

        Listed filtered = list("", "acme");

        assertThat(filtered.incomplete).singleElement().asString().contains("2 organisations")
                .contains("21955855, 20582480").contains("single sign-on");

        forge = new Recorded();
        forge.on(API + "/user", classicUser("ada"));
        forge.on(API + GitHubLister.USER_ORGS, status(403));
        forge.on(orgRepos(API, "acme"), json("[]"));
        forge.on(API + GitHubLister.USER_REPOS, json("[]"));

        Listed refused = list("", "acme");

        assertThat(refused.incomplete).singleElement().asString().contains("read:org");
        assertThat(refused.namespaces).as("the owner and the user's own still listed").containsExactly("acme", "ada");
    }

    @Test
    @DisplayName("rate limits: a secondary limit's Retry-After and a primary limit's reset waited out; a long one ends the listing")
    void rateLimits() {
        forge.on(API + "/user", user("ada"));
        forge.sequence(orgRepos(API, "acme"),
                status(403, "Retry-After", "5"),
                status(429, "X-RateLimit-Remaining", "0", "X-RateLimit-Reset",
                        String.valueOf(START.plusSeconds(5 + 30).getEpochSecond())),
                json("[" + repository(101, "acme/api", "private", false, false) + "]"));

        Listed listed = list("", "acme");

        assertThat(slept).containsExactly(Duration.ofSeconds(5), Duration.ofSeconds(30));
        assertThat(listed.repositories).hasSize(1);
        assertThat(listed.unreadable).as("a limit is not a refusal").isEmpty();

        forge = new Recorded();
        forge.on(API + "/user", user("ada"));
        forge.on(orgRepos(API, "acme"), status(403, "X-RateLimit-Remaining", "0", "X-RateLimit-Reset",
                String.valueOf(clock.instant().plusSeconds(3600).getEpochSecond())));

        assertThatThrownBy(() -> list("", "acme")).isInstanceOf(OutboundPager.RateLimitedException.class);
    }

    @Test
    @DisplayName("a 401 is the token's and ends the listing; a next page elsewhere is refused before anything is sent")
    void theTokenAndTheOrigin() {
        forge.on(API + "/user", user("ada"));
        forge.on(orgRepos(API, "acme"), status(401));

        assertThatThrownBy(() -> list("", "acme")).isInstanceOfSatisfying(ForgeListingException.class,
                refused -> assertThat(refused.reason()).isEqualTo(DiscoveryReason.TOKEN_REJECTED));

        forge = new Recorded();
        forge.on(API + "/user", user("ada"));
        forge.on(orgRepos(API, "acme"), json("[" + repository(101, "acme/api", "private", false, false) + "]",
                "Link", "<https://api.github.com.example.net/organizations/9/repos?page=2>; rel=\"next\""));

        assertThatThrownBy(() -> list("", "acme")).isInstanceOf(OutboundPager.CrossOriginPageException.class);
        assertThat(forge.urls()).noneMatch(url -> url.contains("example.net"));
    }

    // ---- The recorded door.

    /** One request as sent: where, the headers, and the addresses the guard let it reach. */
    record Seen(String url, Map<String, String> headers, List<String> addresses) {}

    /** The exchange alone recorded: the guard before it and {@link OutboundJson} around it are the real ones. */
    static final class Recorded extends PinnedHttpSender {

        final List<Seen> seen = new ArrayList<>();
        private final Map<String, Deque<Response>> answers = new HashMap<>();

        void on(String url, Response response) {
            answers.computeIfAbsent(url, ignored -> new ArrayDeque<>()).add(response);
        }

        void sequence(String url, Response... responses) {
            answers.put(url, new ArrayDeque<>(List.of(responses)));
        }

        List<String> urls() {
            return seen.stream().map(Seen::url).toList();
        }

        @Override
        public Response send(Method method, OutboundUrlGuard.Destination destination, Map<String, String> headers,
                String body, Duration timeout, String label, long maxBodyBytes, Optional<PinnedCa> trust) {
            seen.add(new Seen(destination.url(), Map.copyOf(headers),
                    destination.addresses().stream().map(address -> address.getHostAddress()).toList()));
            Deque<Response> queue = answers.get(destination.url());
            if (queue == null || queue.isEmpty()) {
                return new Response(404, "{\"message\":\"Not Found\"}");
            }
            // The last answer of a path stays: a page asked twice is answered twice.
            return queue.size() > 1 ? queue.poll() : queue.peek();
        }
    }

    /** What a listing was told — the discovery's {@code Run}, without its database. */
    final class Listed implements ForgeLister.Listing {

        final List<String> namespaces = new ArrayList<>();
        final List<DiscoveredRepository> repositories = new ArrayList<>();
        final Map<String, String> unreadable = new LinkedHashMap<>();
        final List<String> incomplete = new ArrayList<>();
        private final ForgeClient.Target target;

        Listed(ForgeClient.Target target) {
            this.target = target;
        }

        @Override
        public ForgeClient.Target target() {
            return target;
        }

        @Override
        public String token() {
            return TOKEN;
        }

        @Override
        public OutboundPager pager(Map<String, String> credential) {
            // Every cloud name resolves to one of GitHub's public addresses: PUBLIC_ONLY lets it through.
            OutboundUrlGuard guard = new OutboundUrlGuard(host -> List.of(new byte[] {(byte) 140, 82, 112, 6}));
            OutboundJson outbound = new OutboundJson(forge, guard, new ObjectMapper());
            return outbound.pager(new OutboundPager.Settings(target.address().apiRoot(), target.policy(), "GitHub",
                    credential, target.trust(), START.plus(Duration.ofMinutes(30)), Duration.ofSeconds(60),
                    OutboundJson.TIMEOUT, null), clock, duration -> {
                        slept.add(duration);
                        clock.advance(duration);
                    });
        }

        @Override
        public void namespace(String path) {
            if (!namespaces.contains(path)) {
                namespaces.add(path);
            }
        }

        @Override
        public void unreadable(String path, String reason) {
            namespace(path);
            unreadable.put(path, reason);
        }

        @Override
        public void namespacesIncomplete(String reason) {
            incomplete.add(reason);
        }

        @Override
        public void repositories(List<DiscoveredRepository> page) {
            repositories.addAll(page);
        }

        @Override
        public List<String> languagesWanted() {
            return List.of();
        }

        @Override
        public void language(String forgeId, String language) {
            throw new AssertionError("GitHub's listing carries the language: no request per repository");
        }
    }

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
}

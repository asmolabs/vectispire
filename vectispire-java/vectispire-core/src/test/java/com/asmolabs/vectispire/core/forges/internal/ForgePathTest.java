package com.asmolabs.vectispire.core.forges.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.ForgeAddress;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * A name the forge or a person supplied never chooses the endpoint an adapter asks. Each adapter is driven through
 * the real door — {@link OutboundJson}, the pager, the guard — with a hostile value where a name goes, and what is
 * pinned is the URL each request went to: the hostile characters inside one segment, or no request at all.
 */
@DisplayName("a forge path segment")
class ForgePathTest {

    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String GITLAB = "https://gitlab.example.org/api/v4";
    private static final String GITHUB = "https://api.github.com";

    private GitHubListerTest.Recorded forge;

    @BeforeEach
    void start() {
        forge = new GitHubListerTest.Recorded();
    }

    private OutboundPager pager(String origin, Map<String, String> credential) {
        OutboundUrlGuard guard = new OutboundUrlGuard(host -> List.of(new byte[] {(byte) 140, 82, 112, 6}));
        return new OutboundJson(forge, guard, new ObjectMapper()).pager(new OutboundPager.Settings(origin,
                OutboundPolicy.PUBLIC_ONLY, "forge", credential, Optional.empty(), NOW.plus(Duration.ofMinutes(2)),
                Duration.ofSeconds(60), OutboundJson.TIMEOUT, null), new GitHubListerTest.MovingClock(NOW),
                duration -> {});
    }

    private static PinnedHttpSender.Response json(String body) {
        return new PinnedHttpSender.Response(200, body, Map.of());
    }

    @Test
    @DisplayName("percent-encodes everything but the unreserved characters, the slash included")
    void encoding() {
        assertThat(ForgePath.segment("group/sub/app")).contains("group%2Fsub%2Fapp");
        assertThat(ForgePath.segment("x?y=1#z")).contains("x%3Fy%3D1%23z");
        assertThat(ForgePath.segment("100%25")).as("a percent is encoded, never passed for the server to decode")
                .contains("100%2525");
        assertThat(ForgePath.segment("a b+c*")).as("a path is not a form: no '+' for a space, '*' encoded")
                .contains("a%20b%2Bc%2A");
        assertThat(ForgePath.segment("é")).contains("%C3%A9");
        assertThat(ForgePath.segment("release-1.2_rc~3")).contains("release-1.2_rc~3");
        assertThat(ForgePath.segment("..hidden")).as("dots within a name are a name").contains("..hidden");
    }

    @Test
    @DisplayName("refuses what no segment can carry: a dot segment, an empty one, none")
    void refusals() {
        assertThat(ForgePath.segment("..")).isEmpty();
        assertThat(ForgePath.segment(".")).isEmpty();
        assertThat(ForgePath.segment("...")).isEmpty();
        assertThat(ForgePath.segment("")).isEmpty();
        assertThat(ForgePath.segment(null)).isEmpty();
    }

    @Nested
    @DisplayName("GitLab's listing")
    class GitLabListing {

        @Test
        @DisplayName("asks a project's languages by its id as one segment, and not at all by a dot segment")
        void languages() {
            forge.on(GITLAB + GitLabLister.GROUPS, json("[]"));
            forge.on(GITLAB + GitLabLister.PROJECTS, json("[]"));
            forge.on(GITLAB + "/projects/7/languages", json("{\"Java\":90.0}"));
            Listing listing = new Listing(ForgeKind.GITLAB, "https://gitlab.example.org", null,
                    List.of("7", "1/members?all=", "..", "../user"));

            new GitLabLister().list(listing);

            assertThat(forge.urls()).containsExactly(GITLAB + GitLabLister.GROUPS, GITLAB + GitLabLister.PROJECTS,
                    GITLAB + "/projects/7/languages",
                    GITLAB + "/projects/1%2Fmembers%3Fall%3D/languages",
                    GITLAB + "/projects/..%2Fuser/languages");
            assertThat(listing.languages).containsEntry("7", "Java").containsEntry("1/members?all=", null)
                    .containsEntry("..", null).containsEntry("../user", null);
        }
    }

    @Nested
    @DisplayName("GitLab's review reader")
    class GitLabReview {

        private final GitLabReviewReader reader = new GitLabReviewReader();

        private ReviewReader.Reading read(String forgeId, Optional<String> branch) {
            return reader.read(pager(GITLAB, Map.of()), GITLAB, forgeId, branch, NOW.minus(Duration.ofDays(30)), 30, 500);
        }

        @Test
        @DisplayName("names the project by an encoded id, and refuses a dot segment without a request")
        void project() {
            read("42/approvals?x", Optional.of("main"));
            assertThat(forge.urls()).containsExactly(GITLAB + "/projects/42%2Fapprovals%3Fx");

            forge.seen.clear();
            assertThat(read("..", Optional.of("main"))).isInstanceOf(ReviewReader.Reading.Unreadable.class);
            assertThat(forge.urls()).isEmpty();
        }

        @Test
        @DisplayName("asks the branch's protection and its merge requests with the branch in one segment")
        void branch() {
            String project = GITLAB + "/projects/42";
            forge.on(project, json("{\"id\":42,\"path_with_namespace\":\"group/app\",\"default_branch\":\"main\"}"));
            forge.on(project + "/approvals", json("{\"merge_requests_author_approval\":false}"));
            forge.on(project + "/approval_rules?per_page=100", json("[]"));

            read("42", Optional.of("feature/x#y&z=1"));

            assertThat(forge.urls()).contains(project + "/protected_branches/feature%2Fx%23y%26z%3D1")
                    .anySatisfy(url -> assertThat(url).startsWith(project
                            + "/merge_requests?state=merged&target_branch=feature%2Fx%23y%26z%3D1&updated_after="));
        }

        @Test
        @DisplayName("asks a merge request's approvals by its number as one segment")
        void mergeRequest() {
            String project = GITLAB + "/projects/42";
            Instant since = NOW.minus(Duration.ofDays(30));
            forge.on(project, json("{\"id\":42,\"path_with_namespace\":\"group/app\",\"default_branch\":\"main\"}"));
            forge.on(project + "/approvals", json("{}"));
            forge.on(project + "/approval_rules?per_page=100", json("[]"));
            forge.on(project + "/merge_requests?state=merged&target_branch=main&updated_after=" + since
                    + "&order_by=updated_at&sort=desc&per_page=100", json("[{\"iid\":\"3/../../../user\",\"merged_at\":\""
                    + NOW.minus(Duration.ofDays(1)) + "\",\"author\":{\"id\":7}}]"));

            read("42", Optional.empty());

            assertThat(forge.urls()).contains(project + "/merge_requests/3%2F..%2F..%2F..%2Fuser/approvals")
                    .noneMatch(url -> url.equals(GITLAB + "/user/approvals"));
        }
    }

    @Nested
    @DisplayName("GitHub's review reader")
    class GitHubReview {

        private final GitHubReviewReader reader = new GitHubReviewReader();

        private ReviewReader.Reading read(Optional<String> branch) {
            return reader.read(pager(GITHUB, Map.of()), GITHUB, "101", branch, NOW.minus(Duration.ofDays(30)), 30, 500);
        }

        @Test
        @DisplayName("asks the repository by its owner and its name, each one segment, whatever the forge's full name holds")
        void owner() {
            forge.on(GITHUB + "/repositories/101", json("{\"id\":101,\"full_name\":\"ac me?x#/api\",\"default_branch\":"
                    + "\"main\"}"));

            read(Optional.empty());

            assertThat(forge.urls()).contains(GITHUB + "/repos/ac%20me%3Fx%23/api/rules/branches/main?per_page=100",
                    GITHUB + "/repos/ac%20me%3Fx%23/api/branches/main/protection");
        }

        @Test
        @DisplayName("refuses an owner that is a dot segment without asking anything under it")
        void dotOwner() {
            forge.on(GITHUB + "/repositories/101", json("{\"id\":101,\"full_name\":\"../api\",\"default_branch\":\"main\"}"));

            assertThat(read(Optional.empty())).isInstanceOf(ReviewReader.Reading.Unreadable.class);
            assertThat(forge.urls()).containsExactly(GITHUB + "/repositories/101");
        }

        @Test
        @DisplayName("asks the branch's rules, protection and pull requests with the branch in one segment")
        void branch() {
            forge.on(GITHUB + "/repositories/101", json("{\"id\":101,\"full_name\":\"acme/api\",\"default_branch\":\"main\"}"));

            read(Optional.of("release/1.0?x"));

            assertThat(forge.urls()).contains(GITHUB + "/repos/acme/api/rules/branches/release%2F1.0%3Fx?per_page=100",
                    GITHUB + "/repos/acme/api/branches/release%2F1.0%3Fx/protection",
                    GITHUB + "/repos/acme/api/pulls?state=closed&base=release%2F1.0%3Fx&sort=updated&direction=desc"
                            + "&per_page=100");
        }
    }

    @Nested
    @DisplayName("GitHub's listing")
    class GitHubListing {

        @Test
        @DisplayName("asks a connection's organisation as one segment")
        void organisation() {
            forge.on(GITHUB + GitHubLister.USER, json("{\"login\":\"someone\",\"id\":7,\"type\":\"User\"}"));
            Listing listing = new Listing(ForgeKind.GITHUB, "https://github.com", "acme/../user?", List.of());

            new GitHubLister().list(listing);

            assertThat(forge.urls()).containsExactly(GITHUB + GitHubLister.USER,
                    GITHUB + "/orgs/acme%2F..%2Fuser%3F/repos?type=all&sort=full_name&per_page=100");
        }
    }

    /** A listing that wants the languages of {@code wanted} and records the ones it is told. */
    private final class Listing implements ForgeLister.Listing {

        final Map<String, String> languages = new LinkedHashMap<>();
        private final List<String> wanted;
        private final ForgeClient.Target target;

        Listing(ForgeKind kind, String address, String owner, List<String> wanted) {
            this.target = new ForgeClient.Target(ForgeAddress.of(kind, address), owner, OutboundPolicy.PUBLIC_ONLY,
                    Optional.empty());
            this.wanted = wanted;
        }

        @Override
        public ForgeClient.Target target() {
            return target;
        }

        @Override
        public String token() {
            return "invented-token";
        }

        @Override
        public OutboundPager pager(Map<String, String> credential) {
            return ForgePathTest.this.pager(target.address().apiRoot(), credential);
        }

        @Override
        public void namespace(String path) {}

        @Override
        public void unreadable(String path, String reason) {}

        @Override
        public void namespacesIncomplete(String reason) {}

        @Override
        public void repositories(List<DiscoveredRepository> page) {}

        @Override
        public List<String> languagesWanted() {
            return wanted;
        }

        @Override
        public void language(String forgeId, String language) {
            languages.put(forgeId, language);
        }
    }
}

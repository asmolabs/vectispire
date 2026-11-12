package com.asmolabs.vectispire.core.forges.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * GitLab's reading of the tracked branches (decision 0037 §3) against recorded answers, through the real door as
 * {@link GitHubListerTest} drives GitHub's: what is pinned is each request sent and what the listing was told.
 */
@DisplayName("GitLab's listing of tracked branches")
class GitLabListerTest {

    private static final String TOKEN = "glpat-LISTERLISTERLISTER00"; // gitleaks:allow
    private static final Instant START = Instant.parse("2026-10-03T12:00:00Z");
    private static final String API = "https://gitlab.example.org/api/v4";

    private GitHubListerTest.Recorded forge;

    @BeforeEach
    void start() {
        forge = new GitHubListerTest.Recorded();
        forge.on(API + GitLabLister.GROUPS, json("[]"));
        forge.on(API + GitLabLister.PROJECTS, json("[]"));
    }

    private static PinnedHttpSender.Response json(String body) {
        return new PinnedHttpSender.Response(200, body, Map.of());
    }

    private static PinnedHttpSender.Response status(int status) {
        return new PinnedHttpSender.Response(status, "{\"message\":\"" + status + "\"}", Map.of());
    }

    private static String branch(String project, String name) {
        return API + "/projects/" + project + "/repository/branches/" + name;
    }

    private Listed list(ForgeLister.BranchQuestion... questions) {
        Listed listed = new Listed(List.of(questions));
        new GitLabLister().list(listed);
        return listed;
    }

    @Test
    @DisplayName("asked of the projects wanted, after the listing, with the token; the default branch without a request")
    void asked() {
        forge.on(branch("7", "master"), status(404));
        forge.on(branch("7", "develop"), json("{\"name\":\"develop\"}"));
        forge.on(branch("8", "main"), status(404));
        forge.on(branch("8", "develop"), status(404));

        Listed listed = list(new ForgeLister.BranchQuestion("7", "acme/api", "main"),
                new ForgeLister.BranchQuestion("8", "acme/legacy", "master"));

        assertThat(forge.urls()).containsExactly(API + GitLabLister.GROUPS, API + GitLabLister.PROJECTS,
                branch("7", "master"), branch("7", "develop"), branch("8", "main"), branch("8", "develop"));
        assertThat(forge.seen).allSatisfy(request -> assertThat(request.headers()).containsEntry("PRIVATE-TOKEN", TOKEN));
        assertThat(listed.branches).containsEntry("7", List.of("develop", "main"))
                .as("only the default branch among them: a reading, not an unknown")
                .containsEntry("8", List.of("master"));
    }

    @Test
    @DisplayName("a 403 — a Guest who may not read the code — or another status is unknown, and ends that project's reading")
    void unknown() {
        forge.on(branch("7", "master"), status(403));
        forge.on(branch("8", "master"), status(302));
        forge.on(branch("9", "master"), json("{}"));
        forge.on(branch("9", "develop"), json("{}"));

        Listed listed = list(new ForgeLister.BranchQuestion("7", "acme/api", "main"),
                new ForgeLister.BranchQuestion("8", "acme/web", "main"),
                new ForgeLister.BranchQuestion("9", "acme/docs", "main"));

        assertThat(forge.urls()).as("develop is not asked once master was unknown").doesNotContain(
                branch("7", "develop"), branch("8", "develop"));
        assertThat(listed.branches).containsEntry("7", null).containsEntry("8", null)
                .containsEntry("9", List.of("develop", "main", "master"));
    }

    @Test
    @DisplayName("a forge that stops answering ends the reading, not the run: the rest keep what they had")
    void outage() {
        forge.on(branch("7", "master"), json("{}"));
        forge.on(branch("7", "develop"), json("{}"));
        forge.on(branch("8", "master"), status(503));

        Listed listed = list(new ForgeLister.BranchQuestion("7", "acme/api", "main"),
                new ForgeLister.BranchQuestion("8", "acme/web", "main"),
                new ForgeLister.BranchQuestion("9", "acme/docs", "main"));

        assertThat(listed.branches).as("an outage is not an answer about the repository: nothing written")
                .containsOnlyKeys("7");
        assertThat(listed.left).singleElement().asString().startsWith("2 ").contains("stopped answering");
    }

    @Test
    @DisplayName("a 401 is the token's and ends the run")
    void rejected() {
        forge.on(branch("7", "master"), status(401));

        assertThatThrownBy(() -> list(new ForgeLister.BranchQuestion("7", "acme/api", "main")))
                .isInstanceOfSatisfying(ForgeListingException.class,
                        refused -> assertThat(refused.reason()).isEqualTo(DiscoveryReason.TOKEN_REJECTED));
    }

    @Test
    @DisplayName("nothing tracked, nothing asked")
    void nothingTracked() {
        Listed listed = new Listed(List.of(new ForgeLister.BranchQuestion("7", "acme/api", "main")));
        listed.tracked = List.of();

        new GitLabLister().list(listed);

        assertThat(forge.urls()).containsExactly(API + GitLabLister.GROUPS, API + GitLabLister.PROJECTS);
        assertThat(listed.branches).isEmpty();
    }

    /** What a listing was told — the discovery's {@code Run}, without its database. */
    private final class Listed implements ForgeLister.Listing {

        final Map<String, List<String>> branches = new LinkedHashMap<>();
        final List<String> left = new ArrayList<>();
        List<String> tracked = List.of("main", "master", "develop");
        private final List<ForgeLister.BranchQuestion> questions;
        private final ForgeClient.Target target = new ForgeClient.Target(
                ForgeAddress.of(ForgeKind.GITLAB, "https://gitlab.example.org"), null, OutboundPolicy.PUBLIC_ONLY,
                Optional.empty());

        Listed(List<ForgeLister.BranchQuestion> questions) {
            this.questions = questions;
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
            OutboundUrlGuard guard = new OutboundUrlGuard(host -> List.of(new byte[] {(byte) 140, 82, 112, 6}));
            return new OutboundJson(forge, guard, new ObjectMapper()).pager(new OutboundPager.Settings(
                    target.address().apiRoot(), target.policy(), "GitLab", credential, target.trust(),
                    START.plus(Duration.ofMinutes(30)), Duration.ofSeconds(60), OutboundJson.TIMEOUT, null),
                    new GitHubListerTest.MovingClock(START), duration -> {});
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
            return List.of();
        }

        @Override
        public void language(String forgeId, String language) {}

        @Override
        public List<String> trackedBranches() {
            return tracked;
        }

        @Override
        public List<ForgeLister.BranchQuestion> branchesWanted() {
            return questions;
        }

        @Override
        public void branches(String forgeId, List<String> present) {
            branches.put(forgeId, present);
        }

        @Override
        public void branchesLeft(int count, String why) {
            left.add(count + " " + why);
        }
    }
}

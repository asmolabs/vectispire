package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence.MergedChange;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * GitHub's answer (decision 0037, lot G3) — github.com, the data-residency cloud and Enterprise Server alike.
 *
 * <p><b>The settings, where the token may read them.</b> The rules that apply to the branch ({@code GET
 * /repos/{owner}/{repo}/rules/branches/{branch}}: rulesets, readable with <em>Metadata: read</em>) and its classic
 * protection ({@code …/branches/{branch}/protection}, which needs <em>Administration: read</em> — a 403 there is
 * written down, not a failure). A {@code pull_request} rule or a protection requiring reviews refuses a direct
 * push, and GitHub never lets an author approve their own pull request; a classic protection that does not apply
 * to administrators is not a proof, since they may merge without the review.
 *
 * <p><b>The history.</b> The closed pull requests into the branch, most recently updated first, until one updated
 * before the window — a pull request merged in the window was updated in it — keeping those with a {@code
 * merged_at}; then each one's reviews, a reviewer's latest decision standing (an approval dismissed, or followed by
 * a request for changes, is not one). Reading pull requests needs <em>Pull requests: read</em> on a fine-grained
 * token, which the discovery's <em>Metadata: read</em> does not include: without it GitHub answers 403 or 404, and
 * the line says which permission is missing.
 */
@Component
class GitHubReviewReader implements ReviewReader {

    @Override
    public ForgeKind kind() {
        return ForgeKind.GITHUB;
    }

    @Override
    public Map<String, String> credential(String token) {
        return Map.of("Authorization", "Bearer " + token, "X-GitHub-Api-Version", GitHubClient.API_VERSION);
    }

    @Override
    public Reading read(OutboundPager pager, String api, String forgeId, Optional<String> wanted, Instant since,
            int windowDays, int maxChanges) {
        OutboundJson.Answer repository = pager.get(api + "/repositories/" + ReviewReader.segment(forgeId));
        switch (repository.status()) {
            case 200 -> {
                // Read below.
            }
            case 401 -> {
                return rejected();
            }
            default -> {
                return new Reading.Unreadable("GitHub does not show repository " + forgeId + " to the connection's token "
                        + "(HTTP " + repository.status() + "): deleted, transferred out of the token's reach, or its "
                        + "access revoked.");
            }
        }
        JsonNode body = repository.body().orElse(null);
        String fullName = body == null ? null : text(body, "full_name");
        if (fullName == null || !fullName.contains("/")) {
            return new Reading.Unreadable("GitHub answered repository " + forgeId + " without its full name.");
        }
        Optional<String> branch = wanted.or(() -> Optional.ofNullable(text(body, "default_branch")));
        if (branch.isEmpty()) {
            return new Reading.Unreadable("GitHub names no default branch for " + fullName + ".");
        }
        // The owner and the name, each a path segment of its own.
        String repo = api + "/repos/" + fullName.substring(0, fullName.indexOf('/')) + "/"
                + ReviewReader.segment(fullName.substring(fullName.indexOf('/') + 1));

        Optional<ChangeReviewEvidence.Settings> settings = Optional.empty();
        List<String> unreadSettings = new ArrayList<>();
        int fromRules = -1;
        OutboundJson.Answer rules = pager.get(repo + "/rules/branches/" + ReviewReader.segment(branch.get())
                + "?per_page=100");
        switch (rules.status()) {
            case 200 -> {
                fromRules = 0;
                for (JsonNode rule : array(rules.body().orElse(null))) {
                    if ("pull_request".equals(text(rule, "type"))) {
                        fromRules = Math.max(fromRules,
                                rule.path("parameters").path("required_approving_review_count").asInt(0));
                    }
                }
            }
            case 401 -> {
                return rejected();
            }
            default -> unreadSettings.add("the rules of the branch not readable (HTTP " + rules.status() + ")");
        }
        int fromProtection = -1;
        boolean adminsBound = false;
        OutboundJson.Answer protection = pager.get(repo + "/branches/" + ReviewReader.segment(branch.get())
                + "/protection");
        switch (protection.status()) {
            case 200 -> {
                JsonNode found = protection.body().orElse(null);
                fromProtection = found == null ? 0 : found.path("required_pull_request_reviews")
                        .path("required_approving_review_count").asInt(0);
                adminsBound = found != null && found.path("enforce_admins").path("enabled").asBoolean(false);
            }
            case 401 -> {
                return rejected();
            }
            // GitHub's "Branch not protected".
            case 404 -> fromProtection = 0;
            default -> unreadSettings.add("the branch protection not readable (HTTP " + protection.status()
                    + "): it needs Administration: read");
        }
        if (fromRules >= 0 || fromProtection >= 0) {
            int required = Math.max(fromRules, adminsBound ? fromProtection : -1);
            required = Math.max(required, 0);
            List<String> said = new ArrayList<>();
            if (fromRules >= 0) {
                said.add("rulesets require " + ReviewReader.approvals(fromRules));
            }
            if (fromProtection >= 0) {
                said.add("branch protection requires " + ReviewReader.approvals(fromProtection)
                        + (fromProtection > 0 && !adminsBound ? ", administrators exempt" : ""));
            }
            said.addAll(unreadSettings);
            settings = Optional.of(new ChangeReviewEvidence.Settings(required, true, required > 0,
                    String.join(", ", said) + " on " + branch.get() + ", author approval prevented by GitHub"));
        }

        History history = history(pager, repo, branch.get(), since, maxChanges);
        if (history.rejected()) {
            return rejected();
        }
        return new Reading.Read(new ChangeReviewEvidence("github", fullName, branch.get(), windowDays, settings,
                settings.isPresent() ? Optional.empty() : Optional.of(String.join("; ", unreadSettings)), history.read(),
                history.unread()));
    }

    private record History(Optional<ChangeReviewEvidence.History> read, Optional<String> unread, boolean rejected) {

        static History unread(String why) {
            return new History(Optional.empty(), Optional.of(why), false);
        }

        static final History REJECTED = new History(Optional.empty(), Optional.empty(), true);
    }

    private static History history(OutboundPager pager, String repo, String branch, Instant since, int maxChanges) {
        record Merged(long number, Instant at, String author) {}
        List<Merged> merged = new ArrayList<>();
        boolean complete = true;
        Optional<String> url = Optional.of(repo + "/pulls?state=closed&base=" + ReviewReader.segment(branch)
                + "&sort=updated&direction=desc&per_page=100");
        pages:
        while (url.isPresent()) {
            OutboundJson.Answer page = pager.get(url.get());
            switch (page.status()) {
                case 200 -> {
                    // Read below.
                }
                case 401 -> {
                    return History.REJECTED;
                }
                default -> {
                    return History.unread("GitHub refused the pull requests to this token (HTTP " + page.status()
                            + "): a fine-grained token needs Pull requests: read");
                }
            }
            for (JsonNode request : page.body().filter(JsonNode::isArray).orElseThrow(() ->
                    new OutboundJson.OutboundFailureException("GitHub answered the pull requests with no list."))) {
                Optional<Instant> updated = ReviewReader.instant(request.get("updated_at"));
                if (updated.isPresent() && updated.get().isBefore(since)) {
                    // Sorted by update, newest first: everything after this one was updated before the window.
                    break pages;
                }
                Optional<Instant> at = ReviewReader.instant(request.get("merged_at"));
                if (at.isEmpty() || at.get().isBefore(since)) {
                    continue;
                }
                if (merged.size() == maxChanges) {
                    complete = false;
                    break pages;
                }
                merged.add(new Merged(request.path("number").asLong(), at.get(),
                        request.path("user").path("id").asText("")));
            }
            url = pager.next(page, url.get(), OutboundPager.NextPage.LINK);
        }
        List<MergedChange> changes = new ArrayList<>();
        for (Merged request : merged) {
            // A reviewer's latest decision stands; a comment decides nothing.
            Map<String, String> decided = new HashMap<>();
            Optional<String> reviews = Optional.of(repo + "/pulls/" + request.number() + "/reviews?per_page=100");
            while (reviews.isPresent()) {
                OutboundJson.Answer page = pager.get(reviews.get());
                switch (page.status()) {
                    case 200 -> {
                        // Read below.
                    }
                    case 401 -> {
                        return History.REJECTED;
                    }
                    default -> {
                        return History.unread("GitHub refused the reviews of #" + request.number() + " to this token (HTTP "
                                + page.status() + "): a fine-grained token needs Pull requests: read");
                    }
                }
                for (JsonNode review : array(page.body().orElse(null))) {
                    String state = text(review, "state");
                    String reviewer = review.path("user").path("id").asText("");
                    if (reviewer.isEmpty() || state == null) {
                        continue;
                    }
                    switch (state) {
                        case "APPROVED", "CHANGES_REQUESTED", "DISMISSED" -> decided.put(reviewer, state);
                        default -> {
                            // COMMENTED, PENDING: no decision.
                        }
                    }
                }
                reviews = pager.next(page, reviews.get(), OutboundPager.NextPage.LINK);
            }
            int peers = 0;
            boolean authorApproved = false;
            for (Map.Entry<String, String> decision : decided.entrySet()) {
                if (!decision.getValue().equals("APPROVED")) {
                    continue;
                }
                if (decision.getKey().equals(request.author())) {
                    authorApproved = true;
                } else {
                    peers++;
                }
            }
            changes.add(new MergedChange("#" + request.number(), request.at(), peers, authorApproved));
        }
        changes.sort(java.util.Comparator.comparing(MergedChange::mergedAt).reversed());
        return new History(Optional.of(new ChangeReviewEvidence.History(complete, changes)), Optional.empty(), false);
    }

    private static Reading rejected() {
        return new Reading.Unreadable("GitHub rejected the connection's token (HTTP 401): it is wrong, expired or "
                + "revoked. Replace it on the connection.");
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }

    private static Iterable<JsonNode> array(JsonNode node) {
        return node != null && node.isArray() ? node : List.of();
    }
}

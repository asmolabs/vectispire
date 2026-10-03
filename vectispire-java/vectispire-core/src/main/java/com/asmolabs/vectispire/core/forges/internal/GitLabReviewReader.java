package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence.MergedChange;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * GitLab's answer (decision 0037, lot G3) — gitlab.com, self-managed and Dedicated, Community Edition included,
 * through the {@code read_api} scope the connection already holds.
 *
 * <p><b>The history is the path every edition has.</b> The merged merge requests into the branch, newest first
 * ({@code GET /projects/:id/merge_requests?state=merged&target_branch=…&updated_after=…}: a change merged in the
 * window was updated in it too, so nothing merged in it is left out, and what was only touched in it is filtered
 * by its {@code merged_at}); then, for each, {@code GET /projects/:id/merge_requests/:iid/approvals}, which the
 * Community Edition answers with {@code approved_by} — who approved — though it has no approval rule. An approval
 * by the merge request's author is not a peer's: it is counted nowhere and named in the evidence. The Community
 * Edition has no "prevent approval by author" setting, so this exclusion is the only one there is.
 *
 * <p><b>The settings are the paid tiers'.</b> {@code GET /projects/:id/approvals} ({@code
 * merge_requests_author_approval}), {@code /approval_rules} (the approvals each rule requires, and on which
 * branches) and the branch's protection ({@code push_access_levels}: a push straight to the branch is a change no
 * review sees). The Community Edition answers 404 to the first — the route does not exist there — and the reading
 * says so and goes on with the history. A token below Maintainer may be refused the protection; the settings
 * then prove nothing alone, and the history decides.
 */
@Component
class GitLabReviewReader implements ReviewReader {

    /** GitLab's "No one" in a protected branch's access levels. */
    private static final int NO_ONE = 0;

    @Override
    public ForgeKind kind() {
        return ForgeKind.GITLAB;
    }

    @Override
    public Map<String, String> credential(String token) {
        return Map.of("PRIVATE-TOKEN", token);
    }

    @Override
    public Reading read(OutboundPager pager, String api, String forgeId, Optional<String> wanted, Instant since,
            int windowDays, int maxChanges) {
        String projectUrl = api + "/projects/" + ReviewReader.segment(forgeId);
        OutboundJson.Answer project = pager.get(projectUrl);
        switch (project.status()) {
            case 200 -> {
                // Read below.
            }
            case 401 -> {
                return rejected();
            }
            default -> {
                return new Reading.Unreadable("GitLab does not show project " + forgeId + " to the connection's token "
                        + "(HTTP " + project.status() + "): deleted, moved out of the token's reach, or its access "
                        + "revoked.");
            }
        }
        JsonNode body = project.body().orElse(null);
        String path = body == null ? forgeId : body.path("path_with_namespace").asText(forgeId);
        Optional<String> branch = wanted.or(() -> Optional.ofNullable(body).map(found -> found.path("default_branch"))
                .filter(JsonNode::isTextual).map(JsonNode::asText).filter(name -> !name.isBlank()));
        if (branch.isEmpty()) {
            return new Reading.Unreadable("GitLab names no default branch for " + path + ": the repository is empty.");
        }

        Settings settings = settings(pager, projectUrl, branch.get());
        if (settings.rejected()) {
            return rejected();
        }
        History history = history(pager, projectUrl, branch.get(), since, maxChanges);
        if (history.rejected()) {
            return rejected();
        }
        return new Reading.Read(new ChangeReviewEvidence("gitlab", path, branch.get(), windowDays, settings.read(),
                settings.unread(), history.read(), history.unread()));
    }

    // ------------------------------------------------------------------ settings

    private record Settings(Optional<ChangeReviewEvidence.Settings> read, Optional<String> unread, boolean rejected) {

        static Settings unread(String why) {
            return new Settings(Optional.empty(), Optional.of(why), false);
        }
    }

    private static Settings settings(OutboundPager pager, String projectUrl, String branch) {
        OutboundJson.Answer configuration = pager.get(projectUrl + "/approvals");
        switch (configuration.status()) {
            case 200 -> {
                // Read below.
            }
            case 401 -> {
                return new Settings(Optional.empty(), Optional.empty(), true);
            }
            case 404 -> {
                return Settings.unread("GitLab answers no approval settings (HTTP 404): Community Edition or Free tier, "
                        + "which has no approval rule — judged on the history");
            }
            default -> {
                return Settings.unread("GitLab refused the approval settings to this token (HTTP "
                        + configuration.status() + ")");
            }
        }
        JsonNode authorApproval = configuration.body().map(node -> node.path("merge_requests_author_approval"))
                .orElse(null);
        // true means the author MAY approve; a field GitLab did not state is not "prevented".
        boolean authorPrevented = authorApproval != null && authorApproval.isBoolean() && !authorApproval.asBoolean();

        OutboundJson.Answer protection = pager.get(projectUrl + "/protected_branches/" + ReviewReader.segment(branch));
        boolean protectedBranch;
        boolean pushRefused;
        String push;
        switch (protection.status()) {
            case 200 -> {
                protectedBranch = true;
                pushRefused = pushRefused(protection.body().orElse(null));
                push = pushRefused ? "direct push refused" : "direct push allowed";
            }
            case 401 -> {
                return new Settings(Optional.empty(), Optional.empty(), true);
            }
            case 404 -> {
                protectedBranch = false;
                pushRefused = false;
                push = "branch not protected";
            }
            default -> {
                protectedBranch = false;
                pushRefused = false;
                push = "protection not readable (HTTP " + protection.status() + ")";
            }
        }

        OutboundJson.Answer rules = pager.get(projectUrl + "/approval_rules?per_page=100");
        int required = 0;
        switch (rules.status()) {
            case 200 -> {
                for (JsonNode rule : array(rules.body().orElse(null))) {
                    if (applies(rule, branch, protectedBranch)) {
                        required = Math.max(required, rule.path("approvals_required").asInt(0));
                    }
                }
            }
            case 401 -> {
                return new Settings(Optional.empty(), Optional.empty(), true);
            }
            default -> {
                return Settings.unread("GitLab refused the approval rules to this token (HTTP " + rules.status() + ")");
            }
        }
        String described = "GitLab approval rules require " + ReviewReader.approvals(required) + " on " + branch + ", "
                + (authorPrevented ? "author approval prevented" : "author approval allowed") + ", " + push;
        return new Settings(Optional.of(new ChangeReviewEvidence.Settings(required, authorPrevented, pushRefused,
                described)), Optional.empty(), false);
    }

    /**
     * Whether a rule binds the branch: a regular or any-approver rule (code owners and report rules bind only some
     * changes) naming no branch binds them all; one naming "all protected branches" binds a protected one; one
     * naming branches binds those, a wildcard as GitLab writes it ({@code release/*}).
     */
    static boolean applies(JsonNode rule, String branch, boolean protectedBranch) {
        String type = rule.path("rule_type").asText("regular");
        if (!type.equals("regular") && !type.equals("any_approver")) {
            return false;
        }
        if (rule.path("applies_to_all_protected_branches").asBoolean(false)) {
            return protectedBranch;
        }
        JsonNode branches = rule.path("protected_branches");
        if (!branches.isArray() || branches.isEmpty()) {
            return true;
        }
        for (JsonNode named : branches) {
            if (wildcard(named.path("name").asText(""), branch)) {
                return true;
            }
        }
        return false;
    }

    private static boolean wildcard(String pattern, String branch) {
        StringBuilder regex = new StringBuilder();
        for (String part : pattern.split("\\*", -1)) {
            if (!regex.isEmpty()) {
                regex.append(".*");
            }
            regex.append(java.util.regex.Pattern.quote(part));
        }
        return branch.matches(regex.toString());
    }

    /** "No one" in every push level, and no user, group or deploy key let through by name. */
    private static boolean pushRefused(JsonNode protection) {
        if (protection == null || !protection.path("push_access_levels").isArray()) {
            return false;
        }
        for (JsonNode level : protection.path("push_access_levels")) {
            if (level.path("access_level").asInt(-1) != NO_ONE || stated(level, "user_id") || stated(level, "group_id")
                    || stated(level, "deploy_key_id")) {
                return false;
            }
        }
        return true;
    }

    private static boolean stated(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return !value.isNull() && !value.isMissingNode();
    }

    /** The elements of a list the forge answered; none for anything else. */
    private static Iterable<JsonNode> array(JsonNode node) {
        return node != null && node.isArray() ? node : List.of();
    }

    // ------------------------------------------------------------------ history

    private record History(Optional<ChangeReviewEvidence.History> read, Optional<String> unread, boolean rejected) {

        static History unread(String why) {
            return new History(Optional.empty(), Optional.of(why), false);
        }

        static final History REJECTED = new History(Optional.empty(), Optional.empty(), true);
    }

    private static History history(OutboundPager pager, String projectUrl, String branch, Instant since, int maxChanges) {
        record Merged(String iid, Instant at, String author) {}
        List<Merged> merged = new ArrayList<>();
        boolean complete = true;
        Optional<String> url = Optional.of(projectUrl + "/merge_requests?state=merged&target_branch="
                + ReviewReader.segment(branch) + "&updated_after=" + since + "&order_by=updated_at&sort=desc&per_page=100");
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
                    return History.unread("GitLab refused the merge requests to this token (HTTP " + page.status()
                            + "): it needs the read_api scope and at least the Reporter role on the project");
                }
            }
            for (JsonNode request : page.body().filter(JsonNode::isArray).orElseThrow(() ->
                    new OutboundJson.OutboundFailureException("GitLab answered the merge requests with no list."))) {
                Optional<Instant> at = ReviewReader.instant(request.get("merged_at"))
                        .or(() -> ReviewReader.instant(request.get("closed_at")))
                        .or(() -> ReviewReader.instant(request.get("updated_at")));
                if (at.isEmpty() || at.get().isBefore(since)) {
                    continue;
                }
                if (merged.size() == maxChanges) {
                    complete = false;
                    break pages;
                }
                merged.add(new Merged(request.path("iid").asText(), at.get(), request.path("author").path("id").asText("")));
            }
            url = pager.next(page, url.get(), OutboundPager.NextPage.GITLAB);
        }
        List<MergedChange> changes = new ArrayList<>();
        for (Merged request : merged) {
            OutboundJson.Answer approvals = pager.get(projectUrl + "/merge_requests/" + request.iid() + "/approvals");
            switch (approvals.status()) {
                case 200 -> {
                    // Read below.
                }
                case 401 -> {
                    return History.REJECTED;
                }
                default -> {
                    return History.unread("GitLab refused the approvals of !" + request.iid() + " to this token (HTTP "
                            + approvals.status() + ")");
                }
            }
            Set<String> peers = new HashSet<>();
            boolean authorApproved = false;
            for (JsonNode approval : array(approvals.body().map(node -> node.path("approved_by")).orElse(null))) {
                String approver = approval.path("user").path("id").asText("");
                if (approver.isEmpty()) {
                    continue;
                }
                if (approver.equals(request.author())) {
                    authorApproved = true;
                } else {
                    peers.add(approver);
                }
            }
            changes.add(new MergedChange("!" + request.iid(), request.at(), peers.size(), authorApproved));
        }
        changes.sort(java.util.Comparator.comparing(MergedChange::mergedAt).reversed());
        return new History(Optional.of(new ChangeReviewEvidence.History(complete, changes)), Optional.empty(), false);
    }

    private static Reading rejected() {
        return new Reading.Unreadable("GitLab rejected the connection's token (HTTP 401): it is wrong, expired or "
                + "revoked. Replace it on the connection.");
    }
}

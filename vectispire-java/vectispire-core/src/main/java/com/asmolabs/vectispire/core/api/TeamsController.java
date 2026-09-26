package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import com.asmolabs.vectispire.core.services.TeamAdministrationService;
import com.asmolabs.vectispire.core.services.TeamAdministrationService.TeamView;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Managing teams. Administrators only, enforced at the entry point.
 *
 * <p>Why teams exist beside per-account assignment, and why the two are unioned, is set out on
 * {@link TeamAdministrationService}, which holds the rules.
 */
@RestController
@RequestMapping("/api/v1/teams")
@RequiresAdministrator
public class TeamsController {

    private final TeamAdministrationService teams;

    public TeamsController(TeamAdministrationService teams) {
        this.teams = teams;
    }

    /**
     * @param memberCount and {@code targetCount} on the list, so the administration screen can
     *     say "four people, two repositories" without one request per team. A team with no
     *     targets grants nothing, and that is worth seeing at a glance rather than by opening it
     * @param notified whether this team has its own channel — <b>and not the URL</b>. A webhook
     *     URL is a bearer capability: whoever reads it can post in the channel where the team
     *     awaits Vectispire's alerts, which is where a forged message carries most weight. The
     *     settings catalogue makes the same choice for the global one
     */
    public record TeamSummary(
            Long id, String name, String description, int memberCount, int targetCount, boolean notified) {}

    public record TeamRequest(String name, String description) {}

    /**
     * @param url the channel, or empty to remove it. Write-only by construction: there is no route
     *     that returns it, so an account that should not have it cannot read it back out of the
     *     screen that sets it
     */
    public record WebhookRequest(String url) {}

    /**
     * A grant as the screen sends it: {@code repository}, {@code container} or {@code project}.
     * What comes back is a {@code TargetGrant}, which adds the target's name.
     */
    public record TeamTargetAssignment(String kind, Long id) {}

    @GetMapping
    public List<TeamSummary> list() {
        return teams.list().stream().map(TeamsController::summaryOf).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public TeamSummary create(
            @RequestBody TeamRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(teams.create(
                body == null ? null : body.name(),
                body == null ? null : body.description(),
                actor(principal, request)));
    }

    @PatchMapping("/{id}")
    public TeamSummary rename(
            @PathVariable long id,
            @RequestBody TeamRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(teams.rename(
                id,
                body == null ? null : body.name(),
                body == null ? null : body.description(),
                actor(principal, request)));
    }

    /**
     * Deletes a team, with its memberships, targets and channel removed explicitly — see
     * {@link TeamAdministrationService#delete} for why the cascade cannot be trusted with it.
     */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        teams.delete(id, actor(principal, request));
    }

    @GetMapping("/{id}/members")
    public List<Long> members(@PathVariable long id) {
        return teams.members(id);
    }

    /** Replaces the membership wholesale, so that removing somebody is something the screen can do. */
    @PutMapping("/{id}/members")
    public List<Long> setMembers(
            @PathVariable long id,
            @RequestBody List<Long> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return teams.replaceMembers(id, body == null ? List.of() : body, actor(principal, request));
    }

    @GetMapping("/{id}/targets")
    public List<TargetNaming.TargetGrant> targets(@PathVariable long id) {
        return teams.targets(id);
    }

    @PutMapping("/{id}/targets")
    public List<TargetNaming.TargetGrant> setTargets(
            @PathVariable long id,
            @RequestBody List<TeamTargetAssignment> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        // Null entries are carried through rather than filtered here: skipping them is the
        // service's rule, and `Stream.toList` keeps nulls.
        List<TeamAdministrationService.TargetAssignment> requested = (body == null ? List.<TeamTargetAssignment>of() : body)
                .stream()
                .map(assignment -> assignment == null
                        ? null
                        : new TeamAdministrationService.TargetAssignment(assignment.kind(), assignment.id()))
                .toList();
        return teams.replaceTargets(id, requested, actor(principal, request));
    }

    /**
     * Sets or clears this team's channel. Validated against the outbound guard as it is typed;
     * empty falls back to the global webhook.
     */
    @PutMapping("/{id}/webhook")
    public TeamSummary setWebhook(
            @PathVariable long id,
            @RequestBody WebhookRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(teams.setWebhook(id, body == null ? null : body.url(), actor(principal, request)));
    }

    /** The principal's own name, agents included, as this route has always attributed it. */
    private static RequestActor actor(VectispirePrincipal principal, HttpServletRequest request) {
        return RequestActors.named(principal == null ? null : principal.getName(), request);
    }

    private static TeamSummary summaryOf(TeamView view) {
        return new TeamSummary(
                view.team().getId(),
                view.team().getName(),
                view.team().getDescription(),
                view.memberCount(),
                view.targetCount(),
                view.notified());
    }
}

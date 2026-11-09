package com.asmolabs.vectispire.core.targets.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.ProjectView;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService.ProjectDetail;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Changing a project, and filing repositories and container images into it (decision 0023, and its
 * amendment of 2026-09-30 for images). Administrators only; a
 * project is created under its solution, {@code POST /api/v1/solutions/{id}/projects}, and read
 * in the tree — or on its own, the one route here an account and a read key reach.
 *
 * <p><b>Filing is an access change.</b> A grant on a project resolves at each request into the
 * repositories and images filed in it, so each of the four filing routes moves visibility for that
 * project's grantees at once. The service audits it in those words.
 */
@Tag(name = "Solutions", description = "Solutions, their projects and the repositories and images filed in them")
@RestController
@RequestMapping("/api/v1/projects")
@RequiresAdministrator
public class ProjectsController {

    private final SolutionAdministrationService administration;
    private final SolutionQueryService query;
    private final VisibilityService visibility;

    public ProjectsController(
            SolutionAdministrationService administration, SolutionQueryService query, VisibilityService visibility) {
        this.administration = administration;
        this.query = query;
        this.visibility = visibility;
    }

    /**
     * A reporting plugin asks about the project it reports on, with a read key; reading the whole tree to
     * find one node would hand it every other project the key's account sees.
     */
    @Operation(summary = "Project", description = "One project as its node in the solutions tree describes it — its "
            + "solution named, its repositories and images, open issues by severity over both, partial, "
            + "checklistsVisible, detected languages — as far as the caller may see. The tree's rule decides: a caller "
            + "sees the project when it sees everything, holds the project as such, or sees one of its repositories or "
            + "images; a project that does not exist and one the caller sees nothing of both answer 404, \"Project not "
            + "found.\".")
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/{id}")
    public ProjectDetail get(@PathVariable long id, @AuthenticationPrincipal VectispirePrincipal principal) {
        return query.project(id, allowanceOf(principal));
    }

    /**
     * On a change, an absent field is left alone and an empty description clears it; a
     * {@code solutionId} moves the project to that solution, with its repositories, images, grants and
     * checklists.
     *
     * <p>A move is a field of the change rather than a route of its own: the solution is already a
     * property of the project this route answers ({@code ProjectView.solutionId}), and a rename and a
     * move sent together are one write, checked once against the destination's names.
     */
    public record ProjectChange(String name, String description, Long solutionId) {}

    @Operation(summary = "Rename, describe or move project", description = "A solutionId moves the project to that "
            + "solution; its repositories, images, grants, checklists, plugin activations and SARIF sources follow it. The "
            + "solution it is already in changes nothing. A solution that does not exist answers 404. A name the "
            + "solution the project ends up in already holds, case aside — a rename, a move, or both — answers 409 with "
            + "the type urn:vectispire:problem:" + SolutionAdministrationService.ProjectNameTakenException.CAUSE + ".")
    @PatchMapping("/{id}")
    public ProjectView update(
            @PathVariable long id,
            @RequestBody ProjectChange body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return administration.updateProject(
                id,
                body == null ? null : body.name(),
                body == null ? null : body.description(),
                body == null ? null : body.solutionId(),
                allowed(principal),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Delete project", description = "Its repositories and images return to no project and its "
            + "grants are revoked; no repository, no image and no finding is deleted.")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.deleteProject(id, RequestActors.of(principal, request));
    }

    /** Files the repository here, moving it out of any other project. Repeating it changes nothing. */
    @Operation(summary = "File repository into project", description = "Moves it out of the project it was in, if "
            + "any. A repository the caller cannot see answers 404, as one that does not exist.")
    @PutMapping("/{id}/repositories/{repositoryId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void file(
            @PathVariable long id,
            @PathVariable long repositoryId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.fileRepository(id, repositoryId, allowed(principal), RequestActors.of(principal, request));
    }

    @Operation(summary = "Remove repository from project", description = "Back to no project. 404 when the "
            + "repository is not in this project.")
    @DeleteMapping("/{id}/repositories/{repositoryId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void unfile(
            @PathVariable long id,
            @PathVariable long repositoryId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.removeRepository(id, repositoryId, allowed(principal), RequestActors.of(principal, request));
    }

    /** Files the image here, moving it out of any other project. Repeating it changes nothing. */
    @Operation(summary = "File container image into project", description = "Moves it out of the project it was "
            + "in, if any; the project's grantees see it from then on. An image the caller cannot see answers 404, as "
            + "one that does not exist.")
    @PutMapping("/{id}/containers/{containerId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void fileContainer(
            @PathVariable long id,
            @PathVariable long containerId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.fileContainer(id, containerId, allowed(principal), RequestActors.of(principal, request));
    }

    @Operation(summary = "Remove container image from project", description = "Back to no project. 404 when the "
            + "image is not in this project.")
    @DeleteMapping("/{id}/containers/{containerId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void unfileContainer(
            @PathVariable long id,
            @PathVariable long containerId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.removeContainer(id, containerId, allowed(principal), RequestActors.of(principal, request));
    }

    /** The caller's visibility with the projects it holds as such: a granted project is read while it holds nothing. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}

package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.services.targets.SolutionAdministrationService.ProjectView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Changing a project, and filing repositories into it (decision 0023). Administrators only; a
 * project is created under its solution, {@code POST /api/v1/solutions/{id}/projects}, and read
 * in the tree.
 *
 * <p><b>Filing is an access change.</b> A grant on a project resolves at each request into the
 * repositories filed in it, so each of the two repository routes moves visibility for that
 * project's grantees at once. The service audits it in those words.
 */
@Tag(name = "Solutions", description = "Solutions, their projects and the repositories filed in them")
@RestController
@RequestMapping("/api/v1/projects")
@RequiresAdministrator
public class ProjectsController {

    private final SolutionAdministrationService administration;
    private final VisibilityService visibility;

    public ProjectsController(SolutionAdministrationService administration, VisibilityService visibility) {
        this.administration = administration;
        this.visibility = visibility;
    }

    /** On a change, an absent field is left alone and an empty description clears it. */
    public record ProjectChange(String name, String description) {}

    @Operation(summary = "Rename or describe project")
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
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Delete project", description = "Its repositories return to no project and its grants "
            + "are revoked; no repository and no finding is deleted.")
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

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}

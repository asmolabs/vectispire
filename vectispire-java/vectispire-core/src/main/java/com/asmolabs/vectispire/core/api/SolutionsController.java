package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.services.targets.SolutionAdministrationService.ProjectView;
import com.asmolabs.vectispire.core.services.targets.SolutionAdministrationService.SolutionView;
import com.asmolabs.vectispire.core.services.targets.SolutionQueryService;
import com.asmolabs.vectispire.core.services.targets.SolutionQueryService.SolutionTree;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Solutions and the projects they hold (decision 0023).
 *
 * <p>Reading the tree takes an account and shows what that account may see — a project it holds a
 * grant on or one of whose repositories it sees; changing it takes an administrator. The rules
 * live in {@link SolutionAdministrationService} and {@link SolutionQueryService}.
 */
@Tag(name = "Solutions", description = "Solutions, their projects and the repositories filed in them")
@RestController
@RequestMapping("/api/v1/solutions")
// The method's marker wins over the class's: every write below is an administrator's.
@RequiresAccount
public class SolutionsController {

    private final SolutionAdministrationService administration;
    private final SolutionQueryService tree;
    private final VisibilityService visibility;

    public SolutionsController(
            SolutionAdministrationService administration, SolutionQueryService tree, VisibilityService visibility) {
        this.administration = administration;
        this.tree = tree;
        this.visibility = visibility;
    }

    /** A name and a description; on a change, an absent field is left alone and an empty description clears it. */
    public record SolutionRequest(String name, String description) {}

    public record ProjectRequest(String name, String description) {}

    @Operation(summary = "Solutions tree", description = "Solutions, their projects and the repositories filed in "
            + "them, as far as the caller may see, with each project's open issues by severity and the repositories "
            + "in no project as a group of their own.")
    @GetMapping
    public SolutionTree list(@AuthenticationPrincipal VectispirePrincipal principal) {
        return tree.tree(allowanceOf(principal));
    }

    @Operation(summary = "Create solution")
    @RequiresAdministrator
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SolutionView create(
            @RequestBody SolutionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return administration.createSolution(
                body == null ? null : body.name(),
                body == null ? null : body.description(),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Rename or describe solution")
    @RequiresAdministrator
    @PatchMapping("/{id}")
    public SolutionView update(
            @PathVariable long id,
            @RequestBody SolutionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return administration.updateSolution(
                id,
                body == null ? null : body.name(),
                body == null ? null : body.description(),
                RequestActors.of(principal, request));
    }

    /** 409 while the solution still holds a project: its projects are deleted first, each on its own. */
    @Operation(summary = "Delete solution", description = "Refused with 409 while the solution holds projects.")
    @RequiresAdministrator
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.deleteSolution(id, RequestActors.of(principal, request));
    }

    /**
     * The caller's visibility, with the projects it holds a grant on beside it — a granted project
     * appears in the tree even while it holds no repository.
     */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }

    @Operation(summary = "Create project in solution")
    @RequiresAdministrator
    @PostMapping("/{id}/projects")
    @ResponseStatus(HttpStatus.CREATED)
    public ProjectView createProject(
            @PathVariable long id,
            @RequestBody ProjectRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return administration.createProject(
                id,
                body == null ? null : body.name(),
                body == null ? null : body.description(),
                RequestActors.of(principal, request));
    }
}

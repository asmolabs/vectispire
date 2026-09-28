package com.asmolabs.vectispire.core.plugins.web;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresPlatformGovernor;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.plugins.SarifSourceService;
import com.asmolabs.vectispire.core.plugins.SarifSourceView;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The declared internal sources — of SARIF, coverage and test reports (decisions 0017 §7, 0032 §7).
 *
 * <p><b>Declaring one is the platform governor's</b>: it is the platform saying "this producer is
 * inside the organisation, and may deposit findings for this project" — the kind of rule
 * {@code Role.governsPlatform} exists for. Reading the declarations is governance, answered to the
 * roles that see the whole estate.
 */
@Tag(name = "SARIF import", description = "SARIF from declared internal sources")
@RestController
@RequestMapping("/api/v1/sarif-sources")
public class SarifSourcesController {

    private final SarifSourceService sources;

    public SarifSourcesController(SarifSourceService sources) {
        this.sources = sources;
    }

    /**
     * @param projectId and {@code repositoryId}: exactly one — the one scope the source may deliver for
     * @param tools each run's {@code tool.driver.name} the source may deliver, compared without case —
     *     for a source delivering {@code sarif}, and none otherwise
     * @param kinds {@code sarif}, {@code coverage}, {@code test_report}; absent is {@code sarif} alone
     */
    public record SourceDeclaration(
            String slug,
            String name,
            @JsonProperty("api_key_id") UUID apiKeyId,
            @JsonProperty("project_id") Long projectId,
            @JsonProperty("repository_id") Long repositoryId,
            List<String> tools,
            List<String> kinds) {}

    public record SourceEnabled(boolean enabled) {}

    @Operation(summary = "List SARIF sources")
    @GetMapping
    @RequiresGovernanceRead
    public List<SarifSourceView> list() {
        return sources.list();
    }

    @Operation(summary = "Declare SARIF source", description = "Platform governor only. Binds an integration key to one "
            + "project or repository and the report kinds it may deliver — sarif (the key holds sarif_import, and the "
            + "tools are named), coverage and test_report (the key holds report_import). Kinds absent: sarif alone.")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPlatformGovernor
    public SarifSourceView declare(
            @RequestBody SourceDeclaration body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        if (body == null) {
            throw new InvalidInputException("A source declaration is required.");
        }
        return sources.declare(
                new SarifSourceService.Declaration(
                        body.slug(), body.name(), body.apiKeyId(), body.projectId(), body.repositoryId(), body.tools(),
                        body.kinds()),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Enable or disable SARIF source", description = "Platform governor only.")
    @PutMapping("/{id}/enabled")
    @RequiresPlatformGovernor
    public SarifSourceView setEnabled(
            @PathVariable long id,
            @RequestBody SourceEnabled body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        if (body == null) {
            throw new InvalidInputException("Say whether the source is enabled.");
        }
        return sources.setEnabled(id, body.enabled(), RequestActors.of(principal, request));
    }

    @Operation(summary = "Remove SARIF source", description = "Platform governor only. The issues it imported stay.")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @RequiresPlatformGovernor
    public void delete(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        sources.delete(id, RequestActors.of(principal, request));
    }
}

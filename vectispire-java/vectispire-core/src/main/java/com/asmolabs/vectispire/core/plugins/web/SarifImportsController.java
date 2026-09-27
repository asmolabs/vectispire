package com.asmolabs.vectispire.core.plugins.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.plugins.SarifImportService;
import com.asmolabs.vectispire.core.plugins.SarifImportView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * A declared internal source's SARIF, deposited into one repository's backlog.
 *
 * <p><b>Only with a declared source's integration key</b> — {@code @AcceptsApiKey(SARIF_IMPORT)} lets
 * such a key reach the route, and the service refuses anything else, a session included. The account
 * the key acts for must be able to cause effects ({@code @RequiresWriteAccount}): an import opens and
 * resolves issues. The repository is resolved in the key's visibility and the source's scope, and one
 * outside either answers 404, like one that does not exist. The body is capped by the route's filter
 * ({@code vectispire.http.max-body.sarif-import}) before it is read.
 */
@Tag(name = "SARIF import", description = "SARIF from declared internal sources")
@RestController
@RequestMapping("/api/v1/repositories/{repositoryId}/sarif-imports")
public class SarifImportsController {

    private final SarifImportService imports;
    private final VisibilityService visibility;

    public SarifImportsController(SarifImportService imports, VisibilityService visibility) {
        this.imports = imports;
        this.visibility = visibility;
    }

    @Operation(summary = "Import SARIF report", description = "A declared internal source's integration key only "
            + "(scope sarif_import). The report's tools must be declared for the source; every run must have succeeded "
            + "and carry results; locations are relative to the repository. 403 for an undeclared key or tool, 404 for "
            + "a repository outside the key's visibility or the source's scope, 413 past the size ceiling.")
    @PostMapping(consumes = {"application/json", "application/sarif+json"})
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    @AcceptsApiKey(ApiKeyScope.SARIF_IMPORT)
    public SarifImportView importReport(
            @PathVariable long repositoryId,
            @RequestBody byte[] document,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return imports.importReport(repositoryId, document, principal.integration().map(integration ->
                new SarifImportService.Uploader(
                        integration.keyId(),
                        integration.keyName(),
                        allowed(principal),
                        RequestActors.of(principal, request))));
    }

    @Operation(summary = "List repository's SARIF imports", description = "The latest fifty. 404 for a repository the "
            + "caller cannot see.")
    @GetMapping
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.READ)
    public List<SarifImportView> history(
            @PathVariable long repositoryId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return imports.history(repositoryId, allowed(principal));
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}

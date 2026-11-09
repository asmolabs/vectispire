package com.asmolabs.vectispire.core.reportplugins.web;

import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.reportplugins.ReportDocumentStatusService;
import com.asmolabs.vectispire.core.reportplugins.ReportDocumentStatusView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A report document's standing, asked by its holder (decision 0035 §4, lot R7). The service decides what the caller
 * may be told; this maps the request.
 *
 * <p>{@code @RequiresAccount} and no integration key: 0035 §4 answers "a signed-in holder", and the answer names a
 * project, which only a caller who sees it whole is shown.
 */
@Tag(name = "Report plugins", description = "Signed container images turning a project export into one document")
@RestController
@RequestMapping("/api/v1/report-documents")
public class ReportDocumentsController {

    private final ReportDocumentStatusService documents;
    private final VisibilityService visibility;

    public ReportDocumentsController(ReportDocumentStatusService documents, VisibilityService visibility) {
        this.documents = documents;
        this.visibility = visibility;
    }

    @Operation(summary = "Get report document status", description = "Whether this installation still stands by a "
            + "report document, named by its SHA-256 — of the package a download handed out, or of the file inside it "
            + "(the provenance's subject); 64 hexadecimal characters, a sha256: prefix accepted, 400 otherwise. "
            + "standing is upheld, withdrawn — the platform governor withdrew the manifest that produced it: its "
            + "signature still verifies, but the installation no longer stands by it — or unknown. productions lists "
            + "the runs that produced it, newest first: project, plugin, manifest and image digests, produced at, the "
            + "signing key's id, whether the package is still kept, and the withdrawal's instant, author and "
            + "justification. Only documents of projects the caller sees whole are shown: one never produced here, "
            + "one of a deleted project and one of a project the caller does not see whole all answer unknown, "
            + "alike. Always 200 for a well-formed digest.")
    @GetMapping("/{sha256}")
    @RequiresAccount
    public ReportDocumentStatusView documentStatus(
            @PathVariable String sha256, @AuthenticationPrincipal VectispirePrincipal principal) {
        return documents.status(sha256, allowanceOf(principal));
    }

    /** The account's grant intersected with the credential's restriction, with the projects granted as such. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }
}

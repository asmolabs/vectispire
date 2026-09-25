package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.exports.CsafDocument;
import com.asmolabs.vectispire.common.domain.exports.SarifLog;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.core.api.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.ExportQueryService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The formats Vectispire hands to somebody else: a code-scanning platform, an auditor, a
 * spreadsheet.
 *
 * <p>The documents are built by the domain and assembled by {@link ExportQueryService}. This
 * controller refuses a target the caller may not see and sets the headers — deliberately all it
 * is allowed to do.
 */
@RestController
@RequestMapping("/api/v1/targets/{kind}/{id}")
@RequiresAccount
public class ExportsController {

    private final ExportQueryService exports;
    private final VisibilityService visibility;

    public ExportsController(ExportQueryService exports, VisibilityService visibility) {
        this.exports = exports;
        this.visibility = visibility;
    }

    /**
     * The backlog as SARIF 2.1.0.
     *
     * <p>What takes a finding out of the dashboard and puts it on the merge request that
     * introduced it.
     */
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping("/issues.sarif")
    public ResponseEntity<SarifLog> sarif(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String kind,
            @PathVariable long id) {
        ScanTarget target = requireVisible(principal, kind, id);
        SarifLog document = exports.sarif(target);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("vectispire-" + kind + "-" + id + ".sarif"))
                .contentType(MediaType.parseMediaType("application/sarif+json"))
                .body(document);
    }

    /** The triage decisions as OpenVEX; the caller may name the author. */
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping("/vex")
    public ResponseEntity<OpenVexDocument> vex(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String author) {
        ScanTarget target = requireVisible(principal, kind, id);
        OpenVexDocument document = exports.openVex(target, author);

        // Downloaded like the other three. It used to render in the tab, which is fine for a
        // developer poking at the API and useless for the button that hands the document to
        // somebody downstream.
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("vectispire-" + kind + "-" + id + ".openvex.json"))
                .contentType(MediaType.APPLICATION_JSON)
                .body(document);
    }

    /**
     * The triage decisions as OASIS CSAF 2.0 (VEX profile).
     */
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping("/issues.csaf.json")
    public ResponseEntity<CsafDocument> csaf(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String author) {
        ScanTarget target = requireVisible(principal, kind, id);
        CsafDocument document = exports.csaf(target, author);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("vectispire-" + kind + "-" + id + ".csaf.json"))
                .contentType(MediaType.parseMediaType("application/vnd.oasis.csaf+json; version=2.0"))
                .body(document);
    }

    /**
     * The posture, as something a person reads.
     *
     * <p>The other exports go to machines — a code host, a downstream consumer, a spreadsheet.
     * This one goes to an auditor or a steering committee.
     */
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping("/posture.pdf")
    public ResponseEntity<byte[]> pdf(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String state) {
        ScanTarget target = requireVisible(principal, kind, id);
        byte[] document = exports.posturePdf(target, state);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("vectispire-" + kind + "-" + id + ".pdf"))
                .contentType(MediaType.APPLICATION_PDF)
                .body(document);
    }

    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping("/issues.csv")
    public ResponseEntity<String> csv(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String state) {
        ScanTarget target = requireVisible(principal, kind, id);
        String document = exports.csv(target, state);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("vectispire-" + kind + "-" + id + ".csv"))
                .contentType(MediaType.parseMediaType("text/csv; charset=utf-8"))
                .body(document);
    }

    /**
     * An export is the widest read in the API — the whole backlog of one target, in one file.
     * It is therefore the route where a missing check costs most, and the one a caller reaches
     * by guessing a number rather than by clicking a link.
     */
    private ScanTarget requireVisible(VectispirePrincipal principal, String kind, long id) {
        ScanTarget target = targetOf(kind, id);
        Visibilities.requireVisible(
                target,
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        return target;
    }

    private static ScanTarget targetOf(String kind, long id) {
        if ("repository".equals(kind)) {
            return new ScanTarget.Repository(id);
        }
        if ("container".equals(kind)) {
            return new ScanTarget.Container(id);
        }
        throw new IllegalArgumentException("Unknown target kind: " + kind + ". Expected \"repository\" or \"container\".");
    }

    /**
     * The filename the browser saves under.
     *
     * <p>Built from the kind and the numeric id and never from the target's name: a name is
     * operator-supplied text, and operator-supplied text in a {@code Content-Disposition} header
     * is a header-injection point.
     */
    private static String attachment(String filename) {
        return "attachment; filename=\"" + filename + "\"";
    }
}

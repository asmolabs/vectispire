package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.HistoryQueryService;
import com.asmolabs.vectispire.core.services.TriageHistory;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import java.util.List;
import org.springframework.http.ContentDisposition;
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
 * The trail that shows a finding was taken into account.
 *
 * <p><b>Not another view of the backlog.</b> The issues screen answers "what is open now"; this
 * one answers "what did we see, when, on which version, and what did we decide about it" — the
 * question asked by somebody who has to be convinced after the fact, and who was not there.
 *
 * <p>Three facts are joined here that live apart in the schema, and the joining is the whole
 * feature: a scan carries the version of the tree it read, a finding links that scan to an
 * issue, and a triage event carries the decision taken on that issue. Separately each is
 * unremarkable; together they are "CVE-2026-1 detected on 2.4.1 the 3rd, accepted the 7th by
 * alice because the vulnerable code is not reachable, still absent from 2.5.0". The join is
 * {@link HistoryQueryService}'s, and so is the masking of repository URLs every format carries.
 *
 * <p><b>The decisions are not filtered by the scan.</b> An acceptance recorded in March still
 * governs the scan that runs in June, so a decision is shown with the issue it applies to
 * regardless of when it was taken. Keying decisions to scans would show each one once and lose
 * it from every later page.
 */
@RestController
@RequestMapping("/api/v1/history")
@RequiresAccount
public class HistoryController {

    private final HistoryQueryService history;
    private final VisibilityService visibility;

    public HistoryController(HistoryQueryService history, VisibilityService visibility) {
        this.history = history;
        this.visibility = visibility;
    }

    @GetMapping("/repositories")
    public List<TriageHistory.Repository> repositories(@AuthenticationPrincipal VectispirePrincipal principal) {
        return history.repositories(visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    @GetMapping("/repositories/{id}")
    public TriageHistory.Dossier dossier(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long id,
            @RequestParam(required = false, defaultValue = "50") int limit) {

        // 404 rather than 403 for a repository the caller was not given, in the words an absent
        // one gets — see `Visibilities`, whose rule the service applies.
        return history.dossier(id, limit, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    @GetMapping(value = "/repositories/{id}/export.csv", produces = "text/csv")
    public ResponseEntity<byte[]> csv(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {

        return download(
                history.csv(id, visibility.of(principal.user().orElse(null), principal.credentialRestriction())),
                MediaType.parseMediaType("text/csv"),
                "vectispire-history-" + id + ".csv");
    }

    @GetMapping(value = "/repositories/{id}/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {

        return download(
                history.pdf(id, visibility.of(principal.user().orElse(null), principal.credentialRestriction())),
                MediaType.APPLICATION_PDF,
                "vectispire-history-" + id + ".pdf");
    }

    /**
     * <b>An attachment, not an inline document.</b> Without the disposition a browser renders
     * the payload in the tab, which is how the OpenVEX export used to arrive — a document meant
     * to be filed, displayed as text and never saved.
     */
    private static ResponseEntity<byte[]> download(byte[] body, MediaType type, String filename) {
        return ResponseEntity.ok()
                .contentType(type)
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(filename).build().toString())
                .body(body);
    }
}

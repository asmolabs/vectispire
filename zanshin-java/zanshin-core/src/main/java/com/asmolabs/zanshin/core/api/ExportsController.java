package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.exports.ExportableIssue;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.exports.IssueCsv;
import com.asmolabs.zanshin.common.domain.exports.OpenVexDocument;
import com.asmolabs.zanshin.common.domain.exports.OpenVexExport;
import com.asmolabs.zanshin.common.domain.exports.SarifExport;
import com.asmolabs.zanshin.common.domain.exports.SarifLog;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.repositories.IssueFilters;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.services.ExportProperties;
import com.asmolabs.zanshin.core.services.GateService;
import com.asmolabs.zanshin.core.services.VisibilityService;
import com.asmolabs.zanshin.core.services.IssueViews;
import com.asmolabs.zanshin.core.services.PostureReport;
import com.asmolabs.zanshin.core.services.TargetNaming;
import java.time.Clock;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.data.domain.PageRequest;
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
 * The three formats Zanshin hands to somebody else: a code-scanning platform, an auditor, a
 * spreadsheet.
 *
 * <p>The documents are built by the domain. This controller only picks the issues and sets the
 * headers — deliberately all it is allowed to do.
 */
@RestController
@RequestMapping("/api/v1/targets/{kind}/{id}")
@RequiresAccount
public class ExportsController {

    /**
     * Exports do not paginate: a partial document handed to an auditor would be worse than a
     * heavy one. The ceiling stays as a guard against a pathological backlog.
     */
    private static final int MAX_EXPORTED = 50_000;

    private final Issues issues;
    private final GateService gate;
    private final TargetNaming naming;
    private final ExportProperties properties;
    private final VisibilityService visibility;
    private final Clock clock;

    public ExportsController(
            Issues issues,
            GateService gate,
            TargetNaming naming,
            ExportProperties properties,
            VisibilityService visibility,
            Clock clock) {
        this.issues = issues;
        this.gate = gate;
        this.naming = naming;
        this.properties = properties;
        this.visibility = visibility;
        this.clock = clock;
    }

    /**
     * The backlog as SARIF 2.1.0.
     *
     * <p>What takes a finding out of the dashboard and puts it on the merge request that
     * introduced it. Quality findings carry their own tags: marking them "security" would raise
     * them as security alerts.
     */
    @GetMapping("/issues.sarif")
    public ResponseEntity<SarifLog> sarif(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @PathVariable String kind,
            @PathVariable long id) {
        requireVisible(principal, kind, id);
        String name = targetName(kind, id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("zanshin-" + kind + "-" + id + ".sarif"))
                .contentType(MediaType.parseMediaType("application/sarif+json"))
                .body(SarifExport.build(
                        exportable(kind, id, null),
                        new SarifExport.Options(name, properties.toolVersion(), properties.publicUrl().orElse(null))));
    }

    /**
     * The triage decisions as OpenVEX.
     *
     * <p>The author, the identifier and the timestamp belong to whoever publishes the document:
     * a VEX is an assertion about who said what, and when. The caller may therefore supply the
     * author.
     */
    @GetMapping("/vex")
    public ResponseEntity<OpenVexDocument> vex(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String author) {
        requireVisible(principal, kind, id);

        String name = targetName(kind, id);
        OpenVexDocument document = OpenVexExport.build(
                exportable(kind, id, null),
                new OpenVexExport.Options(
                        author == null || author.isBlank() ? properties.vexAuthor() : author,
                        name,
                        properties.publicUrl().orElse("urn:zanshin") + "/vex/" + kind + "/" + id,
                        clock.instant()));

        // Downloaded like the other three. It used to render in the tab, which is fine for a
        // developer poking at the API and useless for the button that hands the document to
        // somebody downstream.
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("zanshin-" + kind + "-" + id + ".openvex.json"))
                .contentType(MediaType.APPLICATION_JSON)
                .body(document);
    }

    /**
     * The posture, as something a person reads.
     *
     * <p>The other three exports go to machines — a code host, a downstream consumer, a
     * spreadsheet. This one goes to an auditor or a steering committee, and carries the verdict
     * and the observation together: a target nobody scanned passes every policy, and a document
     * that outlives the screen must not let that read as a clean bill of health.
     */
    @GetMapping("/posture.pdf")
    public ResponseEntity<byte[]> pdf(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String state) {
        requireVisible(principal, kind, id);

        ScanTarget target = isRepository(kind) ? new ScanTarget.Repository(id) : new ScanTarget.Container(id);
        // The same construction the Security screen renders, narrowed to one target. Computing
        // the verdict a second way here would let the document and the screen disagree, which
        // is the one disagreement nobody would think to check.
        SecurityOverview.TargetPosture posture = gate.overview(Visibility.only(List.of(target))).targets().stream()
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No " + kind + " with id " + id + "."));

        byte[] document = PostureReport.render(
                new PostureReport.Subject(
                        targetName(kind, id),
                        kind,
                        posture.verdict().passed(),
                        posture.observed(),
                        posture.observation().name().toLowerCase(java.util.Locale.ROOT).replace('_', ' '),
                        posture.policy().describeSource(),
                        posture.lastScan().map(SecurityOverview.LatestScan::createdAt).orElse(null),
                        clock.instant()),
                exportable(kind, id, state));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("zanshin-" + kind + "-" + id + ".pdf"))
                .contentType(MediaType.APPLICATION_PDF)
                .body(document);
    }

    @GetMapping("/issues.csv")
    public ResponseEntity<String> csv(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestParam(required = false) String state) {
        requireVisible(principal, kind, id);

        targetName(kind, id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("zanshin-" + kind + "-" + id + ".csv"))
                .contentType(MediaType.parseMediaType("text/csv; charset=utf-8"))
                .body(IssueCsv.build(exportable(kind, id, state)));
    }

    /**
     * An export is the widest read in the API — the whole backlog of one target, in one file.
     * It is therefore the route where a missing check costs most, and the one a caller reaches
     * by guessing a number rather than by clicking a link.
     */
    private void requireVisible(ZanshinPrincipal principal, String kind, long id) {
        Visibilities.requireVisible(
                isRepository(kind) ? new ScanTarget.Repository(id) : new ScanTarget.Container(id),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    private List<ExportableIssue> exportable(String kind, long targetId, String state) {
        boolean isRepository = isRepository(kind);
        IssueFilters filters = new IssueFilters(
                "all".equals(state) ? null : state,
                null,
                null,
                null,
                isRepository ? targetId : null,
                isRepository ? null : targetId,
                false,
                false,
                null);

        return issues.findAll(filters.toSpecification(), PageRequest.ofSize(MAX_EXPORTED)).stream()
                .map(IssueViews::forExport)
                .toList();
    }

    private String targetName(String kind, long id) {
        TargetNaming.Names names = naming.all();
        String name = isRepository(kind) ? names.repositories().get(id) : names.containers().get(id);
        if (name == null) {
            throw new NoSuchElementException("No " + kind + " with id " + id + ".");
        }
        return name;
    }

    private static boolean isRepository(String kind) {
        if ("repository".equals(kind)) {
            return true;
        }
        if ("container".equals(kind)) {
            return false;
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

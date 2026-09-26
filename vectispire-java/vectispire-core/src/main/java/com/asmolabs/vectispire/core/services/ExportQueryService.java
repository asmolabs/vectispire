package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.exports.CsafDocument;
import com.asmolabs.vectispire.common.domain.exports.CsafExport;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue;
import com.asmolabs.vectispire.common.domain.exports.IssueCsv;
import com.asmolabs.vectispire.common.domain.exports.OpenVexExport;
import com.asmolabs.vectispire.common.domain.exports.SarifExport;
import com.asmolabs.vectispire.common.domain.exports.SarifLog;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.shared.BrandingProperties;
import com.asmolabs.vectispire.core.services.shared.ExportProperties;
import com.asmolabs.vectispire.core.services.shared.ProductVersion;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

/**
 * One target's backlog, as the documents Vectispire hands to somebody else: a code-scanning
 * platform, a downstream consumer, an auditor, a spreadsheet.
 *
 * <p>The documents themselves are built by the domain; this class picks the issues and the names
 * that go into them. <b>It does not check visibility</b> — the caller has already refused a target
 * the reader may not see, before any of these is reached, because an export is the widest read
 * in the API and the check belongs in front of it rather than somewhere inside.
 *
 * <p>A target that does not exist is a {@link NoSuchElementException}, worded as it always was:
 * "No repository with id 7."
 */
@Service
public class ExportQueryService {

    /**
     * Exports do not paginate: a partial document handed to an auditor would be worse than a
     * heavy one. The ceiling stays as a guard against a pathological backlog.
     */
    private static final int MAX_EXPORTED = 50_000;

    private final Issues issues;
    private final GateService gate;
    private final TargetNaming naming;
    private final ExportProperties properties;
    private final BrandingProperties branding;
    private final SlaService sla;
    private final Clock clock;
    private final ProductVersion version;

    public ExportQueryService(
            Issues issues,
            GateService gate,
            TargetNaming naming,
            ExportProperties properties,
            BrandingProperties branding,
            SlaService sla,
            ProductVersion version,
            Clock clock) {
        this.version = version;
        this.issues = issues;
        this.gate = gate;
        this.naming = naming;
        this.properties = properties;
        this.branding = branding;
        this.sla = sla;
        this.clock = clock;
    }

    /**
     * The backlog as SARIF 2.1.0.
     *
     * <p>Quality findings carry their own tags: marking them "security" would raise them as
     * security alerts on the code host.
     */
    public SarifLog sarif(ScanTarget target) {
        String name = targetName(target);
        return SarifExport.build(
                exportable(target, null),
                new SarifExport.Options(name, version.get(), properties.publicUrl().orElse(null)));
    }

    /**
     * The triage decisions as OpenVEX.
     *
     * <p>The author, the identifier and the timestamp belong to whoever publishes the document:
     * a VEX is an assertion about who said what, and when. The caller may therefore supply the
     * author; blank means the configured one.
     */
    public OpenVexDocument openVex(ScanTarget target, String author) {
        String name = targetName(target);
        return OpenVexExport.build(
                exportable(target, null),
                new OpenVexExport.Options(
                        author == null || author.isBlank() ? properties.vexAuthor() : author,
                        name,
                        properties.publicUrl().orElse("urn:vectispire") + "/vex/" + kindOf(target) + "/" + idOf(target),
                        clock.instant()));
    }

    /** The triage decisions as OASIS CSAF 2.0 (VEX profile). */
    public CsafDocument csaf(ScanTarget target, String author) {
        String name = targetName(target);
        return CsafExport.build(
                exportable(target, null),
                new CsafExport.Options(
                        name,
                        author == null || author.isBlank() ? properties.vexAuthor() : author,
                        version.get(),
                        properties.publicUrl().orElse("https://vectispire.internal"),
                        clock.instant()));
    }

    /**
     * The posture, as something a person reads.
     *
     * <p>It carries the verdict and the observation together: a target nobody scanned passes
     * every policy, and a document that outlives the screen must not let that read as a clean
     * bill of health.
     */
    public byte[] posturePdf(ScanTarget target, String state) {
        // The same construction the Security screen renders, narrowed to one target. Computing
        // the verdict a second way here would let the document and the screen disagree, which
        // is the one disagreement nobody would think to check.
        SecurityOverview.TargetPosture posture = gate.overview(Visibility.only(List.of(target))).targets().stream()
                .findFirst()
                .orElseThrow(() -> missing(target));

        return PostureReport.render(
                new PostureReport.Subject(
                        targetName(target),
                        kindOf(target),
                        posture.verdict().passed(),
                        posture.observed(),
                        posture.observation().name().toLowerCase(Locale.ROOT).replace('_', ' '),
                        posture.policy().describeSource(),
                        posture.lastScan().map(SecurityOverview.LatestScan::createdAt).orElse(null),
                        clock.instant(),
                        branding.name()),
                exportable(target, state),
                sla.policy());
    }

    public String csv(ScanTarget target, String state) {
        targetName(target);
        return IssueCsv.build(exportable(target, state));
    }

    /** @param state a triage state, or {@code all} or null for every one of them */
    private List<ExportableIssue> exportable(ScanTarget target, String state) {
        Long repoId = target instanceof ScanTarget.Repository repository ? repository.id() : null;
        Long containerId = target instanceof ScanTarget.Container container ? container.id() : null;
        IssueFilters filters = new IssueFilters(
                "all".equals(state) ? null : state,
                null,
                null,
                null,
                repoId,
                containerId,
                false,
                false,
                null);

        return issues.findAll(filters.toSpecification(), PageRequest.ofSize(MAX_EXPORTED)).stream()
                .map(IssueViews::forExport)
                .toList();
    }

    private String targetName(ScanTarget target) {
        TargetNaming.Names names = naming.all();
        String name = switch (target) {
            case ScanTarget.Repository repository -> names.repositories().get(repository.id());
            case ScanTarget.Container container -> names.containers().get(container.id());
        };
        if (name == null) {
            throw missing(target);
        }
        return name;
    }

    private static NoSuchElementException missing(ScanTarget target) {
        return new NoSuchElementException("No " + kindOf(target) + " with id " + idOf(target) + ".");
    }

    private static String kindOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository ignored -> "repository";
            case ScanTarget.Container ignored -> "container";
        };
    }

    private static long idOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repository.id();
            case ScanTarget.Container container -> container.id();
        };
    }
}

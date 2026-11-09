package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

/**
 * Whether this installation still stands by a document (decision 0035 §4, lot R7): a holder names it by its
 * SHA-256 — the package a download handed out, or the file inside it — and is told whether it was produced here,
 * how, and whether the manifest that produced it has since been withdrawn.
 *
 * <h2>Why the answer is needed at all</h2>
 *
 * <p>A detached signature cannot be un-made: a document produced by an image later found wrong keeps verifying
 * against the published key for as long as the key is published. The withdrawal is the installation's word that it
 * no longer stands by it, and this is where a holder reads that word — {@code cosign} cannot.
 *
 * <h2>Who is answered what</h2>
 *
 * <p><b>A signed-in account, about the documents of projects it sees whole</b> — the guard of the runs and the
 * download, since a production names its project, its plugin and its requester's run. <b>Anything else is {@code
 * unknown}, in the same body</b> as a digest never produced here: a document of a hidden project, of a project seen
 * only in part, or of one since deleted. A distinct answer for "exists, but not yours" would confirm that a project
 * produced that document to anybody who holds a copy, which is what the 404 of every other route here refuses to
 * do. The price is that a holder without the grant learns nothing; the ADR's "signed-in holder" is one who may
 * read the project.
 *
 * <p>The digest is the run's, not the stored package's: a document purged past the evidence window still has
 * copies in the world, and its run still says whether it stands ({@code documentKept} false). A run that did not
 * produce — an output refused included, whose file the run names — is no document this installation signed, and is
 * not one here.
 *
 * <p>Not audited: a read naming nothing the caller could not already read through the project's runs.
 */
@Service
public class ReportDocumentStatusService {

    /**
     * The productions read for one digest: one for a package, a handful at most for a file a deterministic renderer
     * wrote twice — a bound on a query, not a figure anybody reaches.
     */
    static final int PRODUCTIONS = 100;

    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    private final ReportRunRepository runs;
    private final ReportDocumentRepository documents;
    private final ReportWithdrawals withdrawals;
    private final SolutionQueryService projects;

    public ReportDocumentStatusService(
            ReportRunRepository runs,
            ReportDocumentRepository documents,
            ReportWithdrawals withdrawals,
            SolutionQueryService projects) {
        this.runs = runs;
        this.documents = documents;
        this.withdrawals = withdrawals;
        this.projects = projects;
    }

    /**
     * What this installation says of the document with that SHA-256, to this caller.
     *
     * @param sha256 64 hexadecimal characters, either case, with or without a {@code sha256:} prefix
     * @throws InvalidInputException for anything else — said of the request, never of a document
     */
    public ReportDocumentStatusView status(String sha256, VisibilityService.Allowance allowance) {
        String digest = requireSha256(sha256);
        List<ReportRunEntity> produced = runs.producedWithDigest(ReportRunState.PRODUCED.wireName(), digest,
                PageRequest.of(0, PRODUCTIONS));

        Map<Long, Boolean> seenWhole = new HashMap<>();
        List<ReportRunEntity> visible = produced.stream()
                .filter(run -> seenWhole.computeIfAbsent(run.getProjectId(), id -> seesWhole(id, allowance)))
                // The download's second rule, so that this route does not vouch for a document that one refuses.
                .filter(run -> ReportRunTargets.seenBy(run.getExportTargets(), allowance))
                .toList();
        if (visible.isEmpty()) {
            return new ReportDocumentStatusView(digest, ReportDocumentStanding.UNKNOWN, List.of());
        }

        Map<String, ReportWithdrawal> withdrawn = withdrawals.of(visible.stream().map(ReportRunEntity::getManifestDigest)
                .toList());
        List<ReportDocumentProduction> productions = visible.stream()
                .map(run -> production(run, digest, Optional.ofNullable(withdrawn.get(run.getManifestDigest()))))
                .toList();
        // Upheld while any production stands: the same bytes produced under a manifest still standing are still
        // vouched for, whatever another manifest's fate.
        ReportDocumentStanding standing = productions.stream().anyMatch(found -> found.withdrawnAt() == null)
                ? ReportDocumentStanding.UPHELD
                : ReportDocumentStanding.WITHDRAWN;
        return new ReportDocumentStatusView(digest, standing, productions);
    }

    private boolean seesWhole(long projectId, VisibilityService.Allowance allowance) {
        try {
            ReportPluginService.requireWholeProject(projects, projectId, allowance);
            return true;
        } catch (NotFoundException hidden) {
            return false;
        }
    }

    private ReportDocumentProduction production(ReportRunEntity run, String digest,
            Optional<ReportWithdrawal> withdrawal) {
        return new ReportDocumentProduction(
                digest.equals(run.getPackageSha256())
                        ? ReportDocumentProduction.MatchedDigest.PACKAGE
                        : ReportDocumentProduction.MatchedDigest.OUTPUT,
                run.getId(), run.getProjectId(), run.getProjectName(), run.getPluginId(), run.getManifestDigest(),
                run.getImageDigest(), run.getOutputMediaType(), run.getOutputSha256(), run.getPackageSha256(),
                run.getFinishedAt(), run.getSigningKeyId(), documents.existsById(run.getId()),
                withdrawal.map(ReportWithdrawal::withdrawnAt).orElse(null),
                withdrawal.map(ReportWithdrawal::withdrawnBy).orElse(null),
                withdrawal.map(ReportWithdrawal::withdrawalJustification).orElse(null));
    }

    /**
     * The digest as the columns hold it — lower-case: MySQL compares a {@code varchar} without regard to case and
     * PostgreSQL with it, so an upper-case digest would be known on one engine and unknown on the other.
     */
    static String requireSha256(String sha256) {
        String digest = sha256 == null ? "" : sha256.strip().toLowerCase(Locale.ROOT);
        if (digest.startsWith("sha256:")) {
            digest = digest.substring("sha256:".length());
        }
        if (!SHA256.matcher(digest).matches()) {
            throw new InvalidInputException("A document is named by its SHA-256: 64 hexadecimal characters, as "
                    + "sha256sum prints it.");
        }
        return digest;
    }
}

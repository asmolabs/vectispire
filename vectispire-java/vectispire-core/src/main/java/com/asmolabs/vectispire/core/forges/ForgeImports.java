package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.forges.ImportMapping;
import com.asmolabs.vectispire.common.domain.forges.ImportSkip;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * What the selection, the preview and the import of a discovery's repositories say over the wire (decision 0037
 * §4–5): the requests as a screen sends them, and the answers as it shows them. The services decide; these carry.
 */
public final class ForgeImports {

    private ForgeImports() {}

    // ---------------------------------------------------------------------------------------------- the selection

    /**
     * The selection table's filters, as a request spells them; blank is each one's default. See {@code
     * SelectionFilter} for what each does with a value the forge did not give.
     *
     * @param archived {@code hide} (default), {@code show} or {@code only}
     * @param forks {@code hide} (default), {@code show} or {@code only}
     * @param inactiveDays hides a repository whose last activity is older than this many days
     * @param namespace this namespace and everything below it
     * @param path {@code acme/payments/*} — {@code *} any run of characters, {@code ?} one; without either, a search
     * @param personal {@code show} (default), {@code hide} or {@code only}: repositories in a user's own namespace
     * @param present {@code show} (default), {@code hide} or {@code only}: repositories already a target
     */
    public record ForgeSelectionFilters(
            String archived,
            String forks,
            Integer inactiveDays,
            String language,
            String visibility,
            String namespace,
            String path,
            String personal,
            String present) {

        /** The table as it first opens. */
        public static final ForgeSelectionFilters DEFAULT = new ForgeSelectionFilters(null, null, null, null, null, null, null, null, null);
    }

    /**
     * One repository of the discovery as the selection table shows it.
     *
     * @param presentAs the targets whose URL has the identity of this repository's HTTPS or SSH clone URL, whatever
     *     their branch and sub-path — "present (3 targets)" for a monorepo already split; empty when none
     * @param importedAs the target an earlier import from this connection created for it, recognised by the forge's
     *     id even after a rename; null when none
     * @param selectable whether it may be ticked; {@code notSelectable} says why not
     * @param offered whether the selection proposes it ticked: selectable, matching the default filters, and not in a
     *     personal namespace — those are offered unticked (answer 7)
     * @param proposedSolution the solution the forge's layout suggests, before anybody edits it; null for a personal
     *     namespace
     * @param proposedProject the project within it, likewise
     */
    public record ForgeCandidate(
            ForgeRepositoryView repository,
            List<Long> presentAs,
            Long importedAs,
            boolean selectable,
            ImportSkip notSelectable,
            boolean offered,
            String proposedSolution,
            String proposedProject) {}

    /**
     * One page of the table.
     *
     * @param total how many repositories the filters match
     * @param listed how many the discovery listed, whatever the filters
     * @param unjudged per filter ({@code archived}, {@code fork}, {@code activity}, {@code language}, {@code
     *     visibility}), how many repositories it met with a value the forge did not give and could not judge —
     *     kept by a filter that hides, left out by one that requires; only filters that met one are named
     */
    public record ForgeCandidatePage(
            long discoveryId, List<ForgeCandidate> items, long total, int limit, int offset, long listed,
            Map<String, Long> unjudged) {}

    /**
     * A change to the selection.
     *
     * @param selected the forge ids ticked so far
     * @param operation {@code proposed} (the selectable repositories the filters match, personal namespaces
     *     left out), {@code all} (adds every selectable one the filters match), {@code none} (removes every one they
     *     match), {@code invert} (flips the selectable ones they match), {@code add} or {@code remove} ({@code
     *     forgeIds})
     * @param forgeIds for {@code add} and {@code remove}
     */
    public record ForgeSelectionChange(ForgeSelectionFilters filters, List<String> selected, String operation, List<String> forgeIds) {}

    /**
     * The selection after the change: a set of forge ids, in the table's order.
     *
     * @param dropped forge ids that were in the selection or asked for and are not selectable — already a target,
     *     empty, or not listed by the discovery — so the screen can say why they did not stay ticked
     */
    public record ForgeSelection(long discoveryId, List<String> selected, int count, List<String> dropped) {}

    // ------------------------------------------------------------------------------------- the preview, the import

    /**
     * What a preview and an import are given; the same body for both, so that what was previewed is what is
     * imported.
     *
     * @param discoveryId the discovery whose snapshot is read: the connection's latest one that ended completed or
     *     partial
     * @param forgeIds what was ticked — at most 1,000; a larger selection is several imports
     * @param mapping changes to the proposed solutions and projects, per namespace (and below) or per repository
     * @param credentials the clone credential per host; a host left out takes the proposal — the one HTTPS token
     *     bound to it when there is exactly one, none otherwise
     * @param firstScan queue a first scan of each new target, staggered; off by default
     * @param spacingSeconds between two first scans, 10 to 600; 60 by default
     * @param requiredAgentLabel copied onto every new target
     */
    public record ForgeImportRequest(
            Long discoveryId,
            List<String> forgeIds,
            List<ForgeMappingRule> mapping,
            List<ForgeCredentialChoice> credentials,
            Boolean firstScan,
            Integer spacingSeconds,
            String requiredAgentLabel) {}

    /**
     * A change to the proposed mapping (decision 0037 §4): for a namespace and everything below it, or for one
     * repository by its forge id — the solution, the project, or no project. The most specific word on each field
     * wins.
     */
    public record ForgeMappingRule(String namespacePath, String forgeId, String solution, String project, Boolean noProject) {

        public ImportMapping.Rule rule() {
            return new ImportMapping.Rule(namespacePath, forgeId, solution, project, noProject);
        }
    }

    /**
     * The clone credential for the repositories cloned from one host — the host of their HTTPS clone URL. An SSH
     * key clones over the forge's SSH URL, an HTTPS token (bound to that host, decision 0022) over its HTTPS URL;
     * neither, over the HTTPS URL with no credential, for public repositories. The connection's own token never
     * clones.
     */
    public record ForgeCredentialChoice(String host, String sshKeyId, String httpsTokenId) {}

    /**
     * A clone credential as the preview and the result name it — never the secret.
     *
     * @param kind {@code ssh_key}, {@code https_token} or {@code none}
     */
    public record ForgeCredentialView(String kind, UUID id, String name) {}

    /**
     * The credential applied to one host.
     *
     * @param proposed chosen by the proposal rather than by the request
     * @param repositories how many of the new targets clone from it
     */
    public record ForgeHostCredential(String host, ForgeCredentialView credential, boolean proposed, int repositories) {}

    /**
     * One target the import creates.
     *
     * @param solution where it is filed; null for no project
     * @param visibleTo who will see it, in words: administrators, a project's grantees, or everyone
     * @param firstScanNotBefore when its first scan may start; null without one
     * @param warning what the person should know first — a private repository with no credential fails its first
     *     scan with "requires authentication"
     */
    public record ForgePlannedTarget(
            String forgeId,
            String fullPath,
            String url,
            String branch,
            ForgeCredentialView credential,
            String solution,
            String project,
            String visibleTo,
            Instant firstScanNotBefore,
            String warning) {}

    /** A repository asked for and not imported, and why; {@code repositoryIds} the targets it already is. */
    public record ForgeSkippedImport(String forgeId, String fullPath, ImportSkip reason, List<Long> repositoryIds) {}

    /** A repository the import would refuse — the form's refusal, or a mapping it cannot apply. */
    public record ForgeRefusedImport(String forgeId, String fullPath, String refusal) {}

    /** A solution the import files into: {@code existingId} when it is reused, null when it is created. */
    public record ForgeSolutionPlan(String name, Long existingId) {}

    /**
     * A project the import files into: reused ({@code existingId}) with the grants it carries, or created, with
     * none.
     *
     * @param accounts accounts granted the project directly
     * @param teams teams granted it, whose members see it through them
     */
    public record ForgeProjectPlan(String solution, String name, Long existingId, long accounts, long teams, int targets) {}

    /**
     * The first scans: {@code count} of them, one every {@code spacingSeconds}, the first at {@code firstAt}.
     */
    public record ForgeFirstScans(int count, int spacingSeconds, Instant firstAt, Instant lastAt) {}

    /**
     * What an import would do, nothing written.
     *
     * @param defaultIntervalDays the installation's default schedule the new targets take, having none of their
     *     own; 0 when an administrator has set none, and then they are scanned on request only
     * @param visibilityMode {@code everyone} — every signed-in account sees every target — or {@code assigned}
     * @param firstScans null when no first scan was asked for
     */
    public record ForgeImportPreview(
            UUID connectionId,
            long discoveryId,
            List<ForgePlannedTarget> targets,
            List<ForgeSkippedImport> skipped,
            List<ForgeRefusedImport> refused,
            List<ForgeSolutionPlan> solutions,
            List<ForgeProjectPlan> projects,
            List<ForgeHostCredential> credentials,
            long defaultIntervalDays,
            String visibilityMode,
            ForgeFirstScans firstScans) {}

    /** One target an import created. */
    public record ForgeImportedTarget(
            String forgeId, String fullPath, long repositoryId, String url, String solution, String project,
            Long firstScanId, Instant firstScanNotBefore) {}

    /**
     * What an import did.
     *
     * @param skipped what was asked for and not created — replaying the same import skips everything, {@code
     *     already_imported}
     */
    public record ForgeImportResult(
            UUID connectionId,
            long discoveryId,
            List<ForgeImportedTarget> created,
            List<ForgeSkippedImport> skipped,
            List<String> solutionsCreated,
            List<String> projectsCreated,
            ForgeFirstScans firstScans) {}
}

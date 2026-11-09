package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.ToolKeys;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.sarif.InvalidSarifException;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.asmolabs.vectispire.common.domain.sarif.SarifReport;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.IssueSyncService;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceRepository;
import com.asmolabs.vectispire.core.scanning.ObservedFinding;
import com.asmolabs.vectispire.core.settings.RequestBodyLimits;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Importing a declared internal source's SARIF report into a repository's backlog.
 *
 * <h2>Who may, and what is checked, in order</h2>
 *
 * <ol>
 *   <li><b>An integration key, never a session</b> — the route accepts {@code sarif_import} keys, and
 *       a person with a browser is not a source.</li>
 *   <li><b>A key declared as a source, enabled, and delivering SARIF among its kinds.</b> The key
 *       names the source; an undeclared key is refused (403) and the refusal signalled to the SIEM,
 *       since a key presented where it was not declared is either a broken pipeline or a key used for
 *       something it was not issued for.</li>
 *   <li><b>A repository the key sees, inside the source's scope</b> — the account's visibility, the
 *       key's restriction and the declared project or repository, intersected. Outside any of them
 *       answers 404, in the words of a repository that does not exist.</li>
 *   <li><b>A document that reads</b>: the size ceiling, then {@link SarifReport}'s guards — no link,
 *       no location outside the tree, no absolute path at all (the producer's checkout is unknown
 *       here, so a path must be relative), no expansion.</li>
 *   <li><b>Every run a success with results, from a declared tool.</b> A run that failed or computed
 *       nothing is refused rather than read as clean — the report would resolve the tool's whole
 *       backlog on the repository (decision 0007). A tool the source is not declared for is refused
 *       and signalled.</li>
 * </ol>
 *
 * <h2>Then, the same rules as a plugin</h2>
 *
 * <p>Each run's tool is its own scope: {@code import:<source>/<tool>} ({@link ToolKeys}) is the
 * fingerprint's tool key, and the report resolves that tool's open issues on the repository which it
 * no longer carries — never another tool's, never a plugin's, never a scan's. The issues record the
 * provenance an auditor reads: type {@code imported}, the declared source, the SARIF tool's name and
 * version. The import itself is a row, and an audit entry written after the commit.
 */
@Service
public class SarifImportService {

    /** How many imports a repository's history route answers. */
    static final int HISTORY = 50;

    /** How many times an import is folded when an issue changes under it, the first included. */
    static final int FOLD_ATTEMPTS = 5;

    private final SarifSourceRepository sources;
    private final SarifImportRepository imports;
    private final TargetCatalog targets;
    private final IssueSyncService issues;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final ReportedRepositories reported;
    private final Clock clock;
    private final long maxBytes;

    public SarifImportService(
            SarifSourceRepository sources,
            SarifImportRepository imports,
            TargetCatalog targets,
            IssueSyncService issues,
            AuditLogService audit,
            TransactionTemplate transactions,
            ReportedRepositories reported,
            Clock clock,
            RequestBodyLimits limits) {
        this.sources = sources;
        this.imports = imports;
        this.targets = targets;
        this.issues = issues;
        this.audit = audit;
        this.transactions = transactions;
        this.reported = reported;
        this.clock = clock;
        this.maxBytes = limits.sarifImport().toBytes();
    }

    /**
     * Who is uploading, as the route resolved it from an integration key.
     *
     * @param allowed the key's account's visibility intersected with the key's own restriction
     */
    public record Uploader(UUID keyId, String keyName, Visibility allowed, RequestActor actor) {}

    /**
     * @param uploader empty for a caller that is not an integration key — a session — which is refused
     */
    public SarifImportView importReport(long repositoryId, byte[] document, Optional<Uploader> uploader) {
        Uploader caller = uploader.orElseThrow(() -> new SarifImportRefusedException(
                "SARIF is imported with a declared source's integration key; a session is not a source."));

        SarifSourceEntity source = sources.findByApiKeyId(caller.keyId())
                .filter(SarifSourceEntity::getEnabled)
                .orElseThrow(() -> refused(caller, String.valueOf(repositoryId), "the key \"" + caller.keyName()
                        + "\" is not declared as an enabled SARIF source", "This key is not declared as an enabled SARIF source."));
        // A source declared for coverage or test reports alone holds a key that may also carry
        // sarif_import; its declaration, not the key's scopes, says what it may deposit (decision 0032).
        if (!SourceKind.fromStored(source.getKinds()).contains(SourceKind.SARIF)) {
            throw refused(caller, String.valueOf(repositoryId), "source \"" + source.getSlug()
                    + "\" is not declared to deliver SARIF", "Source \"" + source.getSlug() + "\" is not declared to "
                    + "deliver SARIF.");
        }

        RepositoryView repository = targets.repository(repositoryId)
                .filter(found -> caller.allowed().permits(new ScanTarget.Repository(repositoryId)))
                .orElseThrow(() -> new NotFoundException("No repository " + repositoryId + "."));
        if (!inScope(source, repository)) {
            refused(caller, String.valueOf(repositoryId), "source \"" + source.getSlug()
                    + "\" is not declared for repository " + repositoryId, null);
            throw new NotFoundException("No repository " + repositoryId + ".");
        }

        if (document == null || document.length > maxBytes) {
            throw new SarifTooLargeException("The SARIF document is larger than the " + maxBytes + " bytes accepted.");
        }
        // No absolute root: the producer's checkout is unknown here, so every location must be relative.
        SarifReport report = SarifReport.read(document, maxBytes, List.of());
        if (report.runs().isEmpty()) {
            throw new InvalidSarifException("The report carries no run: it analysed nothing, and importing it would "
                    + "read as a clean repository.");
        }

        Set<String> declared = new LinkedHashSet<>(SarifSourceView.tools(source.getTools()));
        Map<String, List<ObservedFinding>> byTool = new LinkedHashMap<>();
        List<String> described = new ArrayList<>();
        int results = 0;
        for (SarifReport.Run run : report.runs()) {
            if (!run.successful()) {
                throw new InvalidSarifException("The run of \"" + run.toolName() + "\" says it did not execute "
                        + "successfully; importing it would resolve what it failed to look at.");
            }
            if (run.results().isEmpty()) {
                throw new InvalidSarifException("The run of \"" + run.toolName() + "\" carries no results: it computed "
                        + "none, which is not the same as finding none.");
            }
            String normalized = run.toolName().strip().toLowerCase(Locale.ROOT);
            if (!declared.contains(normalized)) {
                throw refused(caller, String.valueOf(repositoryId), "source \"" + source.getSlug()
                                + "\" delivered a report from undeclared tool \"" + run.toolName() + "\"",
                        "Source \"" + source.getSlug() + "\" is declared for " + declared + "; this report was produced by \""
                                + run.toolName() + "\".");
            }
            String tool = ToolKeys.imported(source.getSlug(), run.toolName());
            List<ObservedFinding> findings = byTool.computeIfAbsent(tool, key -> new ArrayList<>());
            for (SarifFinding finding : run.results().get()) {
                findings.add(observed(finding, run, tool));
            }
            results += run.results().get().size();
            // The comma separates the entries the view splits back into a list; a tool name cannot hold
            // one (only declared names are accepted, and those are refused with a comma), a version can.
            described.add(run.toolName() + (run.toolVersion() == null ? "" : " " + run.toolVersion().replace(',', ';')));
        }

        String sha256 = Digests.sha256Hex(document);
        String tools = BoundedText.clip(String.join(", ", new LinkedHashSet<>(described)), 1000);
        int resultsCount = results;
        Instant now = clock.instant();
        // Folded again when an issue changed under the fold — a person's triage committed meanwhile, which
        // the issue's revision (V89) refuses to overwrite: the import reads what is committed and goes on,
        // as a scan does, rather than failing the pipeline that sent it.
        SarifImportEntity saved;
        for (int attempt = 1; ; attempt++) {
            try {
                saved = transactions.execute(status -> {
                    List<ObservedFinding> all = byTool.values().stream().flatMap(List::stream).toList();
                    IssueSyncService.SyncResult folded = issues.syncImport(
                            new ScanTarget.Repository(repositoryId), source.getSlug(), byTool.keySet(), all);
                    SarifImportEntity row = new SarifImportEntity();
                    row.setSourceId(source.getId());
                    row.setSourceSlug(source.getSlug());
                    row.setRepoId(repositoryId);
                    row.setTools(tools);
                    row.setToolKeys(String.join(",", new java.util.TreeSet<>(byTool.keySet())));
                    row.setDocumentSha256(sha256);
                    row.setResultsCount(resultsCount);
                    row.setCreatedCount(folded.created());
                    row.setResolvedCount(folded.resolved());
                    row.setReopenedCount(folded.reopened());
                    row.setImportedAt(now);
                    row.setImportedBy(caller.actor() == null || caller.actor().username() == null
                            ? "key:" + caller.keyName() : caller.actor().username());
                    row.setApiKeyId(caller.keyId());
                    SarifImportEntity imported = imports.save(row);
                    reported.announce(repositoryId);
                    return imported;
                });
                break;
            } catch (OptimisticLockingFailureException changed) {
                if (attempt >= FOLD_ATTEMPTS) {
                    throw changed;
                }
            }
        }

        audit.record(caller.actor().entry(AuditOperation.SARIF_IMPORTED, String.valueOf(repositoryId),
                "SARIF from source \"" + source.getSlug() + "\" (" + tools + ") imported into repository " + repositoryId
                        + ": " + resultsCount + " result(s), " + saved.getCreatedCount() + " new, "
                        + saved.getResolvedCount() + " resolved, sha256 " + sha256.substring(0, 12) + "."));
        return SarifImportView.of(saved);
    }

    /**
     * A repository's SARIF imports, newest first, within the caller's visibility — 404 for one it cannot see.
     *
     * <p>The latest {@link #HISTORY} unless a page is asked for — and a page reaches past them, as the report
     * runs' list does. The repository's 404 comes first, so a refused window says nothing of a repository the
     * caller cannot see.
     *
     * @param limit rows per page, or null for the latest {@link #HISTORY} ({@link ListWindow#requested})
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException a window the rule refuses
     */
    public List<SarifImportView> history(long repositoryId, Visibility allowed, Integer limit, Integer offset) {
        targets.repository(repositoryId)
                .filter(found -> allowed.permits(new ScanTarget.Repository(repositoryId)))
                .orElseThrow(() -> new NotFoundException("No repository " + repositoryId + "."));
        PageRequest asked = ListWindow.requested(limit, offset)
                .map(window -> PageRequest.of(window.page(), window.limit()))
                .orElse(PageRequest.of(0, HISTORY));
        return imports.findByRepoIdOrderByImportedAtDescIdDesc(repositoryId, asked).stream()
                .map(SarifImportView::of)
                .toList();
    }

    private static boolean inScope(SarifSourceEntity source, RepositoryView repository) {
        if (source.getRepositoryId() != null) {
            return source.getRepositoryId().equals(repository.id());
        }
        return source.getProjectId() != null && source.getProjectId().equals(repository.projectId());
    }

    /**
     * An imported finding as the backlog folds it: the rule, the relative path, the tool key; the
     * SARIF tool's name as its source, clipped to that column, and its version as provenance.
     */
    private static ObservedFinding observed(SarifFinding finding, SarifReport.Run run, String tool) {
        Severity severity = finding.severity() == null ? Severity.MEDIUM : finding.severity();
        return new ObservedFinding(
                FindingType.IMPORTED.wireName(),
                BoundedText.clip(run.toolName(), 50),
                finding.ruleId(),
                severity.wireName(),
                null,
                null,
                null,
                finding.file(),
                finding.line(),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                false,
                finding.message(),
                tool,
                run.toolName(),
                run.toolVersion());
    }

    /**
     * Records the refusal — the entry, and through it the SIEM event — and returns the exception to
     * throw, or {@code null} when the caller answers something else (a 404 hiding the repository).
     */
    private SarifImportRefusedException refused(Uploader caller, String resource, String why, String answer) {
        audit.record(caller.actor().entry(AuditOperation.SARIF_IMPORT_REFUSED, resource, "SARIF import refused: " + why + "."));
        return answer == null ? null : new SarifImportRefusedException(answer);
    }
}

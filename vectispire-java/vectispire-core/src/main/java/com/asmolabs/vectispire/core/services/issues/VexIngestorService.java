package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.vex.OpenVexStatement;
import com.asmolabs.vectispire.common.domain.vex.VexStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.access.RowVisibility;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Ingests upstream vendor VEX documents (OpenVEX, OASIS CSAF 2.0, and CycloneDX VEX)
 * and cascades automated suppressions across matching codebase issues.
 *
 * <p><b>A document this cannot read says so.</b> It used to try each format in turn behind
 * {@code catch (Exception ignored)} and, having exhausted them, return "nothing ingested" —
 * HTTP 200, no error, no log. So when the OpenVEX model turned out to reject every conformant
 * v0.2.0 document, the endpoint reported perfect health while doing nothing at all, for anyone
 * who tried it.
 *
 * <p>Trying formats in turn is right: a caller uploads a file and should not have to declare its
 * shape. Swallowing the reason is not. What is kept now is <em>why</em> each attempt failed, and
 * a payload that matched no format at all returns that instead of silence.
 *
 * <p><b>An import is a triage decision taken by the person who uploads it.</b> It used to be
 * taken by nobody: the decision was recorded as made by {@code upstream_vex (<author>)}, the author
 * being whatever the uploaded document said; four-eyes was skipped with a hard-coded approval; no
 * audit entry was written; every matching issue on every target was settled whatever the caller
 * could see; and the platform governor — the one role that "causes no effects and approves
 * nothing" — could do it. A single upload marked a CVE not affected across the estate with no
 * trace of who did it, and the dismissal flowed into the signed CSAF, CycloneDX and OpenVEX
 * exports. Now the caller is the actor, the document's author stays in the comment, the caller's
 * visibility bounds the match, four-eyes applies as it does in the interface, the governor is
 * refused, and one audit entry records the import.
 */
@Service
public class VexIngestorService {

    private final Issues issuesRepo;
    private final IssueTriageService triageService;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;

    public VexIngestorService(
            Issues issuesRepo,
            IssueTriageService triageService,
            SettingsService settings,
            AuditLogService audit,
            TransactionTemplate transactions) {
        this.issuesRepo = issuesRepo;
        this.triageService = triageService;
        this.settings = settings;
        this.audit = audit;
        this.transactions = transactions;
        this.json = new ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    public record IngestionResult(
            int statementsProcessed,
            int matchedIssues,
            int triagedIssues,
            List<String> appliedCves) {}

    /** Who imports, what they may see and whether their dismissals settle or wait for approval. */
    private record Importer(IssueDecisionService.Caller caller, boolean canApprove) {}

    /**
     * Imports a document on behalf of {@code caller}.
     *
     * <p>The triage writes share one transaction; the audit entry is written after it commits. The
     * entry opens a transaction of its own, and on SQLite — where the lock is the file — a second
     * connection opened inside the first waits on its write lock until it times out.
     *
     * @throws AccessDeniedException for the platform governor, whose role decides the rules and
     *     takes no triage decision under them
     */
    public IngestionResult ingestPayload(String payload, IssueDecisionService.Caller caller) {
        if (caller.user().flatMap(user -> Role.of(user.role())).map(Role::governsPlatform).orElse(false)) {
            throw new AccessDeniedException(
                    "Importing VEX settles triage decisions, and the platform governor takes none: "
                            + "it decides the rules the others act under.");
        }
        if (payload == null || payload.isBlank()) {
            return new IngestionResult(0, 0, 0, List.of());
        }
        JsonNode root;
        try {
            root = json.readTree(payload);
        } catch (Exception notJson) {
            throw new IllegalArgumentException(
                    "This is not a JSON document: " + firstLineOf(notJson), notJson);
        }

        Importer importer = new Importer(caller, canApprove(caller));
        IngestionResult result = transactions.execute(status -> ingestAuto(root, importer));

        AuditLogService.Record entry = new AuditLogService.Record(
                AuditOperation.ISSUE_TRIAGED,
                result.triagedIssues() + " issues",
                "VEX import: " + result.triagedIssues() + " issue(s) triaged not affected"
                        + (importer.canApprove() ? "" : " (pending approval)")
                        + " for " + result.appliedCves().size() + " vulnerabilit"
                        + (result.appliedCves().size() == 1 ? "y" : "ies")
                        + (result.appliedCves().isEmpty() ? "" : " — " + String.join(", ", result.appliedCves()))
                        + " — per-issue transitions are in each issue's triage history",
                caller.actor(),
                caller.ipAddress(),
                caller.userAgent());
        // Settled by an importer who may approve: findings dismissed by a document, in bulk. Queued
        // for approval, the import is a request and says nothing a SOC needs to hear yet.
        audit.record(importer.canApprove() && result.triagedIssues() > 0
                ? entry.signalling(SecurityEventType.TRIAGE_SETTLED)
                : entry);
        return result;
    }

    /** Four-eyes, exactly as {@code IssueDecisionService} applies it to a decision taken by hand. */
    private boolean canApprove(IssueDecisionService.Caller caller) {
        return !settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED) || caller.user()
                .flatMap(user -> Role.of(user.role()))
                .map(Role::canApproveTriage)
                .orElse(false);
    }

    private IngestionResult ingestAuto(JsonNode root, Importer importer) {
        if (root == null) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        List<String> refusals = new ArrayList<>();

        // 1. CycloneDX VEX detection
        if (root.has("bomFormat") && "CycloneDX".equalsIgnoreCase(root.get("bomFormat").asText())) {
            try {
                CycloneDxDocument cdx = json.treeToValue(root, CycloneDxDocument.class);
                return ingestCycloneDx(cdx, importer);
            } catch (Exception refused) {
                refusals.add("CycloneDX: " + firstLineOf(refused));
            }
        }

        // 2. OpenVEX detection
        if (root.has("statements") || (root.has("@context") && root.get("@context").asText().contains("openvex"))) {
            try {
                OpenVexDocument openVex = json.treeToValue(root, OpenVexDocument.class);
                return ingestOpenVex(openVex, importer);
            } catch (Exception refused) {
                refusals.add("OpenVEX: " + firstLineOf(refused));
            }
        }

        // Fallback: try parsing as OpenVEX
        try {
            OpenVexDocument doc = json.treeToValue(root, OpenVexDocument.class);
            if (doc.statements() != null && !doc.statements().isEmpty()) {
                return ingestOpenVex(doc, importer);
            }
        } catch (Exception refused) {
            refusals.add("OpenVEX: " + firstLineOf(refused));
        }

        // A document nobody could read is the case this method exists to report, not to hide.
        // An empty result and an unreadable file used to be the same answer.
        throw new IllegalArgumentException(refusals.isEmpty()
                ? "No VEX statement was found: the document declares neither CycloneDX nor OpenVEX."
                : "No VEX format could read this document — " + String.join("; ", refusals));
    }

    private IngestionResult ingestCycloneDx(CycloneDxDocument doc, Importer importer) {
        if (doc == null || doc.vulnerabilities() == null || doc.vulnerabilities().isEmpty()) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        String author = doc.metadata() != null && doc.metadata().tools() != null && !doc.metadata().tools().isEmpty()
                ? doc.metadata().tools().get(0).name()
                : "Upstream CycloneDX Provider";

        int matched = 0;
        int triaged = 0;
        List<String> appliedCves = new ArrayList<>();

        for (CycloneDxDocument.Vulnerability vuln : doc.vulnerabilities()) {
            String cveId = vuln.id();
            if (cveId == null || cveId.isBlank()) {
                continue;
            }

            if (vuln.analysis() != null && "not_affected".equalsIgnoreCase(vuln.analysis().state())) {
                List<IssueEntity> matchingIssues = visibleTo(importer, issuesRepo.findByIdentifier(cveId));
                matched += matchingIssues.size();

                com.asmolabs.vectispire.common.domain.issues.VexJustification justification = mapCycloneDxJustification(vuln.analysis().justification());
                // Clipped, not refused: the vendor wrote it, and one long statement must not stop
                // the import half-way through the document with the earlier issues already settled.
                String comment = BoundedText.clip("Upstream CycloneDX VEX by " + author + ": "
                        + (vuln.analysis().detail() != null ? vuln.analysis().detail() : "Declared not affected in CycloneDX BOM."),
                        Triage.MAX_COMMENT_LENGTH);

                for (IssueEntity issue : matchingIssues) {
                    if ("not_affected".equalsIgnoreCase(issue.getTriageStatus())
                            || "resolved".equalsIgnoreCase(issue.getState())) {
                        continue;
                    }

                    triageService.triage(
                            issue.getId(),
                            new Triage.Request(
                                    TriageStatus.NOT_AFFECTED,
                                    importer.caller().actor(),
                                    justification,
                                    comment,
                                    null),
                            importer.canApprove());
                    triaged++;
                }
                appliedCves.add(cveId);
            }
        }

        return new IngestionResult(doc.vulnerabilities().size(), matched, triaged, appliedCves);
    }

    private IngestionResult ingestOpenVex(OpenVexDocument doc, Importer importer) {
        if (doc == null || doc.statements() == null || doc.statements().isEmpty()) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        String author = doc.author() != null ? doc.author() : "Upstream Vendor";
        int matched = 0;
        int triaged = 0;
        List<String> appliedCves = new ArrayList<>();

        for (OpenVexStatement statement : doc.statements()) {
            if (statement.vulnerability() == null) {
                continue;
            }

            String cveId = statement.vulnerability().get("name");
            if (cveId == null || cveId.isBlank()) {
                cveId = statement.vulnerability().get("id");
            }
            if (cveId == null || cveId.isBlank()) {
                continue;
            }

            if (statement.status() == VexStatus.NOT_AFFECTED) {
                List<IssueEntity> matchingIssues = visibleTo(importer, issuesRepo.findByIdentifier(cveId));
                matched += matchingIssues.size();

                com.asmolabs.vectispire.common.domain.issues.VexJustification justification = mapJustification(statement.justification());

                // Clipped for the reason given on the CycloneDX statement above.
                String comment = BoundedText.clip("Upstream VEX statement by " + author + ": "
                        + (statement.impactStatement() != null ? statement.impactStatement() : "Declared not affected by upstream maintainer."),
                        Triage.MAX_COMMENT_LENGTH);

                for (IssueEntity issue : matchingIssues) {
                    if ("not_affected".equalsIgnoreCase(issue.getTriageStatus())
                            || "resolved".equalsIgnoreCase(issue.getState())) {
                        continue;
                    }

                    triageService.triage(
                            issue.getId(),
                            new Triage.Request(
                                    TriageStatus.NOT_AFFECTED,
                                    importer.caller().actor(),
                                    justification,
                                    comment,
                                    null),
                            importer.canApprove());
                    triaged++;
                }
                appliedCves.add(cveId);
            }
        }

        return new IngestionResult(doc.statements().size(), matched, triaged, appliedCves);
    }

    /**
     * The issues the importer may see. A document names a CVE, not a target: without this, one
     * upload settled the CVE on every target in the deployment, including the caller's blind spots.
     */
    private static List<IssueEntity> visibleTo(Importer importer, List<IssueEntity> issues) {
        return issues.stream()
                .filter(issue -> RowVisibility.isVisible(issue, importer.caller().visibility()))
                .toList();
    }

    /** Jackson's messages carry the whole path on later lines; the first says what went wrong. */
    private static String firstLineOf(Exception failure) {
        return String.valueOf(failure.getMessage()).lines().findFirst().orElse(failure.toString());
    }

    /**
     * A missing justification falls back rather than refusing the statement.
     *
     * <p>The specification requires one on {@code not_affected}; a document that omits it is
     * malformed, and dropping the statement would discard an upstream vendor's assertion over a
     * field the triage record does not act on. The fallback is the weakest of the five, so a
     * missing justification never reads as a stronger claim than was made.
     *
     * <p>The translation table that used to live here is gone with the enumeration it translated:
     * one controlled vocabulary now has one Java enum, and mapping a value to itself was the shape
     * that let the two drift.
     */
    private static com.asmolabs.vectispire.common.domain.issues.VexJustification mapJustification(
            com.asmolabs.vectispire.common.domain.issues.VexJustification justification) {
        return justification == null
                ? com.asmolabs.vectispire.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST
                : justification;
    }

    private com.asmolabs.vectispire.common.domain.issues.VexJustification mapCycloneDxJustification(String justification) {
        if (justification == null) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
        }
        String normalized = justification.toLowerCase(Locale.ROOT).replace("-", "_").replace(" ", "_");
        if (normalized.contains("component_not_present")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.COMPONENT_NOT_PRESENT;
        }
        if (normalized.contains("not_in_execute_path") || normalized.contains("not_in_execution_path")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH;
        }
        if (normalized.contains("not_present")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_PRESENT;
        }
        if (normalized.contains("cannot_be_controlled")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
        }
        return com.asmolabs.vectispire.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
    }
}

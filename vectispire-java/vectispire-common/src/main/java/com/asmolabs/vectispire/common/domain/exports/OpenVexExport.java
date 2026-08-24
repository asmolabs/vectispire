package com.asmolabs.zanshin.common.domain.exports;

import com.asmolabs.zanshin.common.domain.crypto.Digests;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Builds an OpenVEX document for a product from its vulnerability issues.
 *
 * <p>Only {@link FindingType#VULNERABILITY} issues are included: VEX is defined over
 * vulnerability identifiers, and a hardcoded secret or a failed IaC check has no CVE to make
 * a statement about. Issues with no identifier are dropped for the same reason — an anonymous
 * statement is not a statement.
 */
public final class OpenVexExport {

    private OpenVexExport() {}

    /**
     * @param timestamp supplied by the caller: a VEX document asserts who said what and when,
     *     which belongs to whoever publishes it and not to a utility function
     */
    public record Options(String author, String productId, String documentId, Instant timestamp, int version) {

        public Options(String author, String productId, String documentId, Instant timestamp) {
            this(author, productId, documentId, timestamp, 1);
        }
    }

    public static OpenVexDocument build(Collection<ExportableIssue> issues, Options options) {
        List<OpenVexDocument.Statement> statements = new ArrayList<>();

        for (ExportableIssue issue : issues) {
            if (issue.type() != FindingType.VULNERABILITY || issue.identifier() == null || issue.identifier().isBlank()) {
                continue;
            }
            statements.add(statement(issue, options));
        }

        return new OpenVexDocument(
                OpenVexDocument.CONTEXT,
                options.documentId(),
                options.author(),
                Digests.canonical(options.timestamp()),
                options.version(),
                "Zanshin",
                List.copyOf(statements));
    }

    private static OpenVexDocument.Statement statement(ExportableIssue issue, Options options) {
        VexStatus status = statusOf(issue);

        // The specification requires a justification for `not_affected`, and the triage
        // service guarantees one exists before the status can be set.
        String justification = status == VexStatus.NOT_AFFECTED ? issue.triageJustification() : null;
        String impact = status == VexStatus.NOT_AFFECTED ? blankToNull(issue.triageComment()) : null;
        // For `affected`, the same free text belongs to the action statement instead.
        String action = status == VexStatus.AFFECTED ? blankToNull(issue.triageComment()) : null;

        OpenVexDocument.Product product = issue.purl() == null || issue.purl().isBlank()
                ? new OpenVexDocument.Product(options.productId(), null)
                : new OpenVexDocument.Product(options.productId(), Map.of("purl", issue.purl()));

        // RFC 3339, as OpenVEX requires. A timestamp with no timezone is not a valid instant
        // under that standard, and a strict consumer is entitled to refuse the document.
        Instant at = issue.triagedAt() != null ? issue.triagedAt() : issue.lastSeenAt();

        return new OpenVexDocument.Statement(
                new OpenVexDocument.Vulnerability(issue.identifier()),
                List.of(product),
                status.wireName(),
                justification,
                impact,
                action,
                at == null ? null : Digests.canonical(at));
    }

    private static VexStatus statusOf(ExportableIssue issue) {
        // An issue that is resolved and was never triaged is factually fixed: the scanner
        // stopped seeing it. Saying "under investigation" about something that is gone would be
        // misleading in a document written to answer exactly that question.
        if (issue.resolved() && VexStatus.of(issue.triageStatus()) == VexStatus.UNDER_INVESTIGATION) {
            return VexStatus.FIXED;
        }
        return VexStatus.of(issue.triageStatus());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}

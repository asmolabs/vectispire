package com.asmolabs.vectispire.common.domain.exports;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.vex.OpenVexStatement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Builds an OpenVEX document for a product from its vulnerability issues.
 *
 * <p><b>It used to build a second OpenVEX model of its own.</b> Two records called
 * {@code OpenVexDocument} lived in this codebase — this package's and {@code domain.vex}'s — on
 * two routes, describing one standard. They disagreed: the other one modelled {@code products} as
 * bare strings, so {@code /api/v1/vex/ingest} could not read what this builder emitted, and the
 * signed advisory in the evidence bundle did not satisfy the version it declared. Neither half
 * could see the other, because nothing ever asked one to read the other's output.
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
        List<OpenVexStatement> statements = new ArrayList<>();

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
                null,
                options.timestamp(),
                options.version(),
                "Vectispire",
                List.copyOf(statements));
    }

    private static OpenVexStatement statement(ExportableIssue issue, Options options) {
        VexStatus status = statusOf(issue);

        // The specification requires a justification for `not_affected`, and the triage
        // service guarantees one exists before the status can be set.
        VexJustification justification = status == VexStatus.NOT_AFFECTED
                ? VexJustification.fromWireName(issue.triageJustification()).orElse(null)
                : null;
        String impact = status == VexStatus.NOT_AFFECTED ? blankToNull(issue.triageComment()) : null;
        // For `affected`, the same free text belongs to the action statement instead.
        String action = status == VexStatus.AFFECTED ? blankToNull(issue.triageComment()) : null;

        OpenVexStatement.Product product = issue.purl() == null || issue.purl().isBlank()
                ? new OpenVexStatement.Product(options.productId(), null)
                : new OpenVexStatement.Product(options.productId(), Map.of("purl", issue.purl()));

        return new OpenVexStatement(
                Map.of("name", issue.identifier()),
                List.of(product),
                statusOfVex(status),
                justification,
                impact,
                action,
                null,
                issue.triagedAt() != null ? issue.triagedAt() : issue.lastSeenAt());
    }

    /**
     * The export's status enumeration, mapped onto the document's.
     *
     * <p>Two enumerations of one vocabulary remain here, and deliberately: this one answers "what
     * does a triage status become in a VEX document", which is a question about Vectispire, while
     * the other is the document's own field. They are kept apart until the mapping itself moves.
     */
    private static com.asmolabs.vectispire.common.domain.vex.VexStatus statusOfVex(VexStatus status) {
        return com.asmolabs.vectispire.common.domain.vex.VexStatus.valueOf(status.name());
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

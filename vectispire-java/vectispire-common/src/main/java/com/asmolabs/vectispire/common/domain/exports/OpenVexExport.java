package com.asmolabs.vectispire.common.domain.exports;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.vex.OpenVexStatement;
import com.asmolabs.vectispire.common.domain.vex.VexDisposition;
import com.asmolabs.vectispire.common.domain.vex.VexStatus;
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
        // The reading CycloneDX and CSAF make of the same triage (decision 0041), spelled in OpenVEX.
        VexDisposition disposition = VexDisposition.of(
                issue.triageStatus(), issue.triageJustification(), issue.resolved());
        String comment = blankToNull(issue.triageComment());

        VexStatus status = switch (disposition.kind()) {
            case NOT_AFFECTED -> VexStatus.NOT_AFFECTED;
            case AFFECTED, WILL_NOT_FIX -> VexStatus.AFFECTED;
            case FIXED -> VexStatus.FIXED;
            case UNDER_INVESTIGATION -> VexStatus.UNDER_INVESTIGATION;
        };
        String impact = status == VexStatus.NOT_AFFECTED ? comment : null;
        // For `affected` the free text is the action statement; for an accepted risk, the action is
        // saying so, which OpenVEX has no status of its own for.
        String action = switch (disposition.kind()) {
            case WILL_NOT_FIX -> "Will not fix: the risk was accepted" + (comment == null ? "." : " — " + comment);
            case AFFECTED -> comment;
            default -> null;
        };

        OpenVexStatement.Product product = issue.purl() == null || issue.purl().isBlank()
                ? new OpenVexStatement.Product(options.productId(), null)
                : new OpenVexStatement.Product(options.productId(), Map.of("purl", issue.purl()));

        return new OpenVexStatement(
                Map.of("name", issue.identifier()),
                List.of(product),
                status,
                disposition.justification().orElse(null),
                impact,
                action,
                null,
                issue.triagedAt() != null ? issue.triagedAt() : issue.lastSeenAt());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}

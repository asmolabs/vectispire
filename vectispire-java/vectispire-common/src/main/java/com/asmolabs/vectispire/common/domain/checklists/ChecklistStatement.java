package com.asmolabs.vectispire.common.domain.checklists;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

/**
 * One revision of a project's checklist as a document states it — {@code checklist.json}, and what the
 * renderer writes into the workbook (decision 0032 §10).
 *
 * <p><b>A contract, not a view.</b> This is the input a report plugin will receive (§10, the P3 block):
 * its field names are the document's, stable across versions, and a field is added — never renamed, never
 * repurposed — with {@link #FORM} raised when a reader could misread the old shape. It is not the API's
 * {@code ChecklistView}, whose shape follows the screens.
 *
 * <p><b>Only what was recorded.</b> A measurement is the one the sign-off froze, or, on a revision not
 * signed off, the one computed for this rendering, and says which ({@link Measured#purpose}); its rule and
 * its evidence are the texts that were applied and judged, each hashing to the digest beside it. A proof's file is named by its SHA-256 and
 * never included. The product version is absent when the build states none, not guessed.
 *
 * @param form the shape of this record; {@value #FORM} for this one
 * @param signed whether this statement is the signed-off revision's, rendered and signed inside its
 *     sign-off; false for a draft, a submitted or a superseded revision rendered on request
 * @param header what the workbook's header cells receive: the product, the author, and the date — the
 *     sign-off instant, absent until there is one, never the moment of rendering (§2)
 * @param fourEyesRequired whether four-eyes approval required the signer to be none of the revision's
 *     authors when it was signed off; absent before
 * @param productVersion the Vectispire version that produced the document, absent when the build does
 *     not state one
 * @param producedAt when the document was produced — the sign-off instant for a signed one
 */
@JsonPropertyOrder({"form", "status", "signed", "project", "revision", "template", "header", "opened", "submitted",
        "signedOff", "fourEyesRequired", "productVersion", "producedAt", "lines"})
public record ChecklistStatement(
        int form,
        String status,
        boolean signed,
        Project project,
        int revision,
        Template template,
        Header header,
        Act opened,
        Act submitted,
        Act signedOff,
        Boolean fourEyesRequired,
        String productVersion,
        Instant producedAt,
        List<Line> lines) {

    public static final int FORM = 1;

    public ChecklistStatement {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(template, "template");
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(opened, "opened");
        Objects.requireNonNull(producedAt, "producedAt");
        lines = List.copyOf(lines);
        if (signed && (signedOff == null || header.date() == null)) {
            throw new IllegalArgumentException("A signed statement names its sign-off and is dated by it.");
        }
    }

    public record Project(long id, String name) {}

    /**
     * @param version the version's number within its template
     * @param sourceSha256 the SHA-256 of the workbook the organisation delivered, which the document's
     *     {@code checklist.xlsx} is that file patched
     */
    @JsonPropertyOrder({"slug", "name", "version", "label", "sourceSha256"})
    public record Template(String slug, String name, int version, String label, String sourceSha256) {}

    /** @param date the sign-off instant; absent on a revision not signed off */
    @JsonPropertyOrder({"product", "author", "date"})
    public record Header(String product, String author, Instant date) {}

    /** Who did something to the revision, and when. */
    public record Act(String by, Instant at) {}

    /**
     * One line of the checklist.
     *
     * @param row the line's row in the template's checklist sheet, where its answer and comment are written
     * @param evidenceRequired {@code none}, {@code link_or_file} or {@code file}: what a "yes" needs
     * @param answer the current answer, absent while the line is unanswered
     * @param history every answer the line was given in this revision, oldest first, the current one last
     * @param measurement the line's measurement, absent when no rule is bound to it
     * @param reconciliation the answer beside the measurement, in {@link Reconciliation}'s words
     * @param evidence every proof attached in this revision, withdrawn ones included and dated as such
     */
    @JsonPropertyOrder({"itemId", "key", "position", "row", "domain", "objective", "control", "contact", "kpi",
            "contentDigest", "evidenceRequired", "evidenceValidityMonths", "answer", "history", "measurement",
            "reconciliation", "evidence"})
    public record Line(
            long itemId,
            String key,
            int position,
            int row,
            String domain,
            String objective,
            String control,
            String contact,
            String kpi,
            String contentDigest,
            String evidenceRequired,
            Integer evidenceValidityMonths,
            Answer answer,
            List<Answer> history,
            Measured measurement,
            String reconciliation,
            List<Proof> evidence) {

        public Line {
            history = List.copyOf(history);
            evidence = List.copyOf(evidence);
        }
    }

    /**
     * An answer as it was given.
     *
     * @param value {@code yes}, {@code no} or {@code not_applicable}
     * @param word the template's own word for it — what the workbook's answer cell holds
     * @param answeredBy the person who gave it; a carried copy keeps theirs, and names its carrier beside it
     */
    @JsonPropertyOrder({"id", "value", "word", "comment", "answeredBy", "answeredAt", "carriedFrom", "carriedBy",
            "carriedAt", "needsConfirmation"})
    public record Answer(
            long id,
            String value,
            String word,
            String comment,
            String answeredBy,
            Instant answeredAt,
            Long carriedFrom,
            String carriedBy,
            Instant carriedAt,
            boolean needsConfirmation) {}

    /**
     * What a rule found.
     *
     * @param purpose {@code sign_off} for the measurement the sign-off froze, {@code submission} for the
     *     last one stored on a revision that was never signed off, {@code read} for one computed for this
     *     rendering and stored nowhere
     * @param rule the bound rule's canonical form as text, exactly as the line held it when it was measured:
     *     its SHA-256 is {@code ruleDigest}
     * @param evidence the evidence as text, exactly as it was judged: its SHA-256 is {@code evidenceDigest}.
     *     Text rather than nested JSON on purpose — a reader re-serialising an object would change its
     *     bytes, and a digest nobody can recompute from the document is a digest nobody can check
     */
    @JsonPropertyOrder({"purpose", "ruleKind", "ruleDigest", "rule", "outcome", "reason", "asOf", "computedAt",
            "summary", "evidenceDigest", "evidence"})
    public record Measured(
            String purpose,
            String ruleKind,
            String ruleDigest,
            String rule,
            String outcome,
            String reason,
            Instant asOf,
            Instant computedAt,
            String summary,
            String evidenceDigest,
            String evidence) {}

    /**
     * A proof: a link, or a file named by its SHA-256.
     *
     * @param kind {@code link} or {@code file}
     */
    @JsonPropertyOrder({"id", "kind", "link", "fileName", "mediaType", "size", "sha256", "performedOn", "validUntil",
            "addedBy", "addedAt", "withdrawnBy", "withdrawnAt"})
    public record Proof(
            long id,
            String kind,
            String link,
            String fileName,
            String mediaType,
            Long size,
            String sha256,
            LocalDate performedOn,
            LocalDate validUntil,
            String addedBy,
            Instant addedAt,
            String withdrawnBy,
            Instant withdrawnAt) {}
}

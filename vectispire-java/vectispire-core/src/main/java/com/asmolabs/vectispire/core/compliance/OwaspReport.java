package com.asmolabs.vectispire.core.compliance;

import java.util.Map;

/**
 * An OWASP review with what its screen links it to: the backlog behind each category it names, and
 * the issues behind each identifier it may cite.
 *
 * @param categoryFindings every Top 10:2021 category, {@code A01} to {@code A10} in that order, with the
 *     number of the repository's open issues of unsettled triage the OWASP grid places there — exactly
 *     what {@code GET /api/v1/issues?repository_id=…&owasp_category=…&unsettled=true} lists for the
 *     caller, so the figure on a link is the length of the list it opens. <b>All ten, a zero
 *     included</b>: a zero is a count somebody can read, and a missing key could be read as "not
 *     counted". The backlog of now, not of the scan the review was written from — a link opens today's
 *     list, and a figure from the past would disagree with it
 * @param issueLinks for each identifier of a finding the model was shown, in the order it was shown, the
 *     repository's open issues carrying exactly that identifier now, as the caller sees them; an
 *     identifier no such issue carries any more is left out. Null when the review recorded no identifier
 *     set (one written before V84): not recorded, which an empty map — "nothing to link" — would misstate
 */
public record OwaspReport(
        AiReviewResultView review, Map<String, Long> categoryFindings, Map<String, IssueLink> issueLinks) {

    /**
     * Where a cited identifier leads.
     *
     * @param issueId the issue, when exactly one carries the identifier; null when several do, and the
     *     link is to a list rather than to an issue
     * @param count how many do, at least one
     */
    public record IssueLink(Long issueId, long count) {}
}

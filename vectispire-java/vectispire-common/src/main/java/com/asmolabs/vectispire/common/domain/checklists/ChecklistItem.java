package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.util.Objects;
import java.util.Optional;

/**
 * One line of a template version: the template's words, as imported and shown as written, and what
 * this version asks of the line.
 *
 * <p>The contact is text — a role, not an account (decision 0032, question 16) — and stays out of
 * the digest: who to ask about a line is not what the line asks.
 *
 * @param position the item's place among the version's items, from 1, in the sheet's order
 * @param row the sheet row the item was read from, which the renderer writes into
 * @param boundRule the canonical form of the rule bound to the line, when one is: the rules are a
 *     later lot's closed set ({@code ChecklistRule}), and each supplies the form its digest reads
 */
public record ChecklistItem(
        ItemKey key,
        int position,
        String domain,
        String objective,
        String control,
        String contact,
        String kpi,
        int row,
        EvidenceRequirement evidence,
        Optional<String> boundRule) {

    /**
     * Ceilings on the template's words, refused rather than clipped: a control cut short asks
     * something else, and an item is the organisation's words or nothing. Well under a cell's
     * 32,767 characters; a line longer than this is a policy, which belongs in the instructions.
     */
    public static final int MAX_LABEL = 1_000;
    public static final int MAX_CONTROL = 4_000;
    public static final int MAX_CONTACT = 255;
    public static final int MAX_KPI = 4_000;

    /** Written into the digest first, so that a change of what it covers is a new prefix, never a collision. */
    private static final String DIGEST_FORM = "vectispire/checklist-item/1";

    public ChecklistItem {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(boundRule, "boundRule");
        if (position < 1) {
            throw new IllegalArgumentException("An item's position counts from 1: " + position);
        }
        if (row < 1) {
            throw new IllegalArgumentException("A sheet row counts from 1: " + row);
        }
        domain = bounded(domain, MAX_LABEL, "domain", row);
        objective = bounded(objective, MAX_LABEL, "objective", row);
        control = bounded(control, MAX_CONTROL, "control", row);
        contact = bounded(contact, MAX_CONTACT, "contact", row);
        kpi = bounded(kpi, MAX_KPI, "KPI", row);
        if (ChecklistText.normalize(control).isEmpty()) {
            throw new InvalidTemplateException("Row " + row + " has no control: a line that asks nothing is not an item.");
        }
    }

    /**
     * SHA-256 over what the line asks, in the order decision 0032 §2 lists it: the normalised
     * domain, objective, control and KPI text, the evidence requirement, and the bound rule.
     * Two versions' items with the same key and the same digest are <em>unchanged</em>, and an
     * answer crosses between them as current; any other difference makes an answer carried onto
     * the line wait for a person's confirmation.
     *
     * <p>NUL-separated by {@link Digests#sha256Fields}, which cannot be imitated from a cell: XML
     * cannot carry the character. The key, the position, the row and the contact stay out — moving a
     * line, renumbering it or naming someone else to ask changes nothing it asks.
     */
    public String contentDigest() {
        return Digests.sha256Fields(
                DIGEST_FORM,
                ChecklistText.normalize(domain),
                ChecklistText.normalize(objective),
                ChecklistText.normalize(control),
                ChecklistText.normalize(kpi),
                evidence.canonical(),
                boundRule.map(rule -> "rule:" + rule).orElse("unbound"));
    }

    public ChecklistItem withKey(ItemKey replacement) {
        return new ChecklistItem(replacement, position, domain, objective, control, contact, kpi, row, evidence, boundRule);
    }

    public ChecklistItem withEvidence(EvidenceRequirement replacement) {
        return new ChecklistItem(key, position, domain, objective, control, contact, kpi, row, replacement, boundRule);
    }

    public ChecklistItem withBoundRule(Optional<String> replacement) {
        return new ChecklistItem(key, position, domain, objective, control, contact, kpi, row, evidence, replacement);
    }

    /** Kept as written, a blank read as empty; the words are the template's, shown as it wrote them. */
    private static String bounded(String value, int max, String what, int row) {
        String kept = value == null ? "" : value.strip();
        if (kept.length() > max) {
            throw new InvalidTemplateException("Row " + row + ": the " + what + " is longer than " + max + " characters.");
        }
        return kept;
    }
}

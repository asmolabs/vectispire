package com.asmolabs.vectispire.core.checklists;

/**
 * What proof one line of a draft asks for before a checklist can be submitted (decision 0032 §2): the
 * line named by its key as the version shows it ({@code items[].itemKey}), the requirement — {@code
 * none}, {@code link_or_file} or {@code file} — and, when a proof expires, for how many months it holds.
 *
 * <p>The components are named as the version's items show them, so that a screen sends back what it read.
 *
 * @param evidenceValidityMonths 1 to 120, or null for a proof that does not expire; always null for {@code none}
 */
public record ChecklistItemEvidence(String itemKey, String evidenceKind, Integer evidenceValidityMonths) {}

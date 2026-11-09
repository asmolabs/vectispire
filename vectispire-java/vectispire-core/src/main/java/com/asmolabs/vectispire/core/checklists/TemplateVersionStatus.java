package com.asmolabs.vectispire.core.checklists;

import java.util.Arrays;
import java.util.Locale;

/**
 * Where a template version stands (decision 0032 §3, §4).
 *
 * <ul>
 *   <li>{@link #DRAFT} — imported or derived, its layout and pairs still being confirmed; nobody
 *       answers it, and at most one exists per template;
 *   <li>{@link #PUBLISHED} — immutable: what projects open their checklists on. A change of layout,
 *       word or binding is a new version;
 *   <li>{@link #RETIRED} — no new checklist opens on it; every checklist already on it stays readable.
 *       A draft set aside is retired too, never having been published.
 * </ul>
 */
public enum TemplateVersionStatus {
    DRAFT,
    PUBLISHED,
    RETIRED;

    /** The value stored in {@code t_checklist_template_version.status} and sent on the wire. */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * The status a stored value names. A value this version does not know is a defect of the row,
     * not the caller's: it is only ever written from this enum.
     */
    static TemplateVersionStatus ofStored(String stored) {
        return Arrays.stream(values())
                .filter(status -> status.wireName().equals(stored))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("A template version has an unknown status: " + stored));
    }
}

package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The profiles a template's contact column names — the people a line is to be asked of, as roles
 * ("PO", "BA", "Arch") — which a project links to its accounts (decision 0044).
 *
 * <p><b>Read from the cells, never from a list written here.</b> The column is the organisation's
 * words: one workbook says "Arch", the next "ARCH", a third adds "SII". A closed list would remind
 * nobody of the profile it forgot, so every value the column holds is a profile but one.
 *
 * <p><b>{@code AUTO} is not a profile.</b> It marks a line Vectispire measures, which nobody is asked to
 * fill in — a rule bound to the line answers it, or the line waits for a person like any other, and
 * then it is the CISO's to chase, not an account named "AUTO".
 *
 * <p><b>One cell may name several.</b> "PO / BA" asks either, so it is both profiles' line: each is
 * reminded of it. A cell is split on {@code /}, which no profile's name carries, and each part
 * compared without case or spacing — "Arch" and "ARCH " are one profile, shown as first written.
 */
public final class ContactProfiles {

    /** The column's marker for a line Vectispire measures, compared like a profile's key. */
    public static final String AUTOMATIC = "AUTO";

    /** Within {@code t_checklist_contact.profile}: a contact cell holds at most 255 characters. */
    public static final int MAX_KEY = ChecklistItem.MAX_CONTACT;

    private static final Pattern SEPARATOR = Pattern.compile("/");

    private ContactProfiles() {}

    /**
     * A profile: the key a link is stored and compared by, and the words a screen shows.
     *
     * @param key the label normalised ({@link ChecklistText#normalize}) and upper-cased
     * @param label the first spelling the column used
     */
    public record Profile(String key, String label) {

        public Profile {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(label, "label");
        }
    }

    /** The profiles one contact cell names, in the order it names them; none for a blank cell or {@code AUTO}. */
    public static List<Profile> of(String contact) {
        if (contact == null) {
            return List.of();
        }
        Map<String, Profile> named = new LinkedHashMap<>();
        for (String part : SEPARATOR.split(contact)) {
            String label = ChecklistText.normalize(part);
            if (label.isEmpty()) {
                continue;
            }
            String key = keyOf(label);
            if (!AUTOMATIC.equals(key)) {
                named.putIfAbsent(key, new Profile(key, label));
            }
        }
        return List.copyOf(named.values());
    }

    /** Every profile the cells name, each once, in the order the column first names it. */
    public static List<Profile> of(Collection<String> contacts) {
        Map<String, Profile> named = new LinkedHashMap<>();
        for (String contact : contacts) {
            for (Profile profile : of(contact)) {
                named.putIfAbsent(profile.key(), profile);
            }
        }
        return List.copyOf(named.values());
    }

    /** The keys one contact cell names — what a reminder groups a line under. */
    public static Set<String> keysOf(String contact) {
        Set<String> keys = new LinkedHashSet<>();
        of(contact).forEach(profile -> keys.add(profile.key()));
        return keys;
    }

    /**
     * The key of a profile as a person or a route names it — the same comparison as the column's, so
     * that "arch" in a request finds the profile the column spelled "Arch".
     *
     * @return empty for a blank name, and for one that holds a {@code /}, which names no single profile
     */
    public static String keyOf(String name) {
        String normalized = ChecklistText.normalize(name);
        if (normalized.isEmpty() || normalized.contains("/")) {
            return "";
        }
        return normalized.toUpperCase(Locale.ROOT);
    }
}

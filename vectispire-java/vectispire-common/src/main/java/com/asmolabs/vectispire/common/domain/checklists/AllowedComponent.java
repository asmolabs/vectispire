package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/**
 * One package an organisation requires, named by a package-URL prefix, and the versions of it it
 * allows (decision 0032 §6, question 11).
 *
 * <p><b>An explicit list, no ordering.</b> "At least 3.2" needs each ecosystem's version order, and an
 * order done wrong passes a line — a later step. A version is allowed when it is written here, as the
 * SBOM states it.
 *
 * <p><b>Nothing of any organisation here.</b> The product ships no package and no version: the rule
 * exists for the organisation that binds it with its own prefixes (question 11), and appears in no
 * template until one does.
 *
 * @param purlPrefix a package URL without its version — {@code pkg:maven/com.example/ledger-core} —
 *     matching a component whose package URL is exactly it, or continues it with {@code @}, {@code /},
 *     {@code ?} or {@code #}: {@code pkg:npm/left} must not match {@code pkg:npm/left-pad}
 * @param versions sorted, distinct
 */
public record AllowedComponent(String purlPrefix, List<String> versions) {

    public static final int MAX_PREFIX = 500;
    public static final int MAX_VERSIONS = 100;
    public static final int MAX_VERSION = 255;

    public AllowedComponent {
        Objects.requireNonNull(purlPrefix, "purlPrefix");
        Objects.requireNonNull(versions, "versions");
        String prefix = purlPrefix.strip();
        if (!prefix.startsWith("pkg:") || prefix.length() <= 4 || prefix.length() > MAX_PREFIX
                || prefix.chars().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c))
                || prefix.contains("@")) {
            throw new InvalidInputException("A package is named by a package URL without its version, pkg:type/"
                    + "namespace/name, at most " + MAX_PREFIX + " characters; \"" + BoundedText.clip(prefix, 60)
                    + "\" is not one.");
        }
        if (versions.isEmpty() || versions.size() > MAX_VERSIONS) {
            throw new InvalidInputException("A package lists 1 to " + MAX_VERSIONS + " allowed versions; "
                    + prefix + " lists " + versions.size() + ".");
        }
        TreeSet<String> sorted = new TreeSet<>();
        for (String version : versions) {
            String kept = version == null ? "" : version.strip();
            if (kept.isEmpty() || kept.length() > MAX_VERSION || kept.chars().anyMatch(Character::isISOControl)) {
                throw new InvalidInputException("An allowed version of " + prefix + " is 1 to " + MAX_VERSION
                        + " characters; one is not.");
            }
            sorted.add(kept);
        }
        purlPrefix = prefix;
        versions = List.copyOf(sorted);
    }

    /** Whether a component's package URL is this package's. */
    boolean names(String purl) {
        if (purl == null || !purl.startsWith(purlPrefix)) {
            return false;
        }
        if (purl.length() == purlPrefix.length()) {
            return true;
        }
        char next = purl.charAt(purlPrefix.length());
        return next == '@' || next == '/' || next == '?' || next == '#';
    }
}

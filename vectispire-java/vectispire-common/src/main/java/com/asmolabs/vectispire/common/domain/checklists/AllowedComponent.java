package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.dependencies.MavenVersionRange;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/**
 * One package an organisation requires, named by a package-URL prefix, and the versions of it it
 * allows (decision 0032 §6, question 11).
 *
 * <p><b>Exact versions, and Maven ranges for Maven packages.</b> An entry that does not open with a
 * bracket or a parenthesis is a version, allowed when the SBOM states exactly it. One that does is a
 * Maven range — {@code [1.17,2.0)}, {@code [1.17.7]}, {@code (,2.0)}, a comma union — read in Maven's
 * order ({@link MavenVersionRange}), and only on a {@code pkg:maven/} prefix: "at least 3.2" needs the
 * ecosystem's own order, an order done wrong passes a line, and Maven's is the only one implemented
 * and checked against its reference. A range on another type is refused when bound, and read from a
 * stored rule stays the literal it was; a stored rule is never refused, its text being its digest. An
 * exact version keeps its meaning whatever the type; on a Maven package a stored entry that reads as a
 * range is read as one, and still matches its literal — no Maven version is written with a bracket.
 *
 * <p><b>Nothing of any organisation here.</b> The product ships no package and no version: the rule
 * exists for the organisation that binds it with its own prefixes (question 11), and appears in no
 * template until one does.
 *
 * @param purlPrefix a package URL without its version — {@code pkg:maven/com.example/ledger-core} —
 *     matching a component whose package URL is exactly it, or continues it with {@code @}, {@code /},
 *     {@code ?} or {@code #}: {@code pkg:npm/left} must not match {@code pkg:npm/left-pad}
 * @param versions sorted, distinct: exact versions and, on a Maven package, ranges
 */
public record AllowedComponent(String purlPrefix, List<String> versions) {

    public static final int MAX_PREFIX = 500;
    public static final int MAX_VERSIONS = 100;
    public static final int MAX_VERSION = 255;

    public AllowedComponent {
        Objects.requireNonNull(versions, "versions");
        String prefix = requirePrefix(purlPrefix);
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

    /**
     * A package as a person declares it on a draft — the canonical constructor's checks, and one more
     * it cannot make.
     *
     * <p><b>A prefix ending on a separator is refused here, never normalised and never in the
     * constructor.</b> {@link #names} takes {@code /}, {@code ?} and {@code #} as the boundary <em>after</em>
     * the prefix, so {@code pkg:maven/com.example/} matched no component at all and the line failed with
     * "is not in its SBOM" while the whole group was there. The constructor also reads every stored rule
     * back ({@link ChecklistRule#fromCanonical}), and the stored text is the content digest (decision
     * 0032 §2, §4): refusing there would make a published version unreadable, stripping there would
     * recompute a digest nobody changed and mark the line changed in the next version. Stripping on this
     * path alone would store something other than what the person wrote, beside a form showing what they
     * wrote; the refusal names the prefix that works instead.
     */
    static AllowedComponent declared(String purlPrefix, List<String> versions) {
        AllowedComponent component = new AllowedComponent(purlPrefix, versions);
        for (String version : component.versions()) {
            if (!MavenVersionRange.looksLikeRange(version)) {
                continue;
            }
            if (!component.maven()) {
                throw new InvalidInputException("A version range is read in Maven's order, and applies to a pkg:maven/"
                        + " package only; " + BoundedText.clip(component.purlPrefix(), 60) + " is not one — list the"
                        + " versions it allows.");
            }
            MavenVersionRange.parse(version);
        }
        refuseEndingOnSeparator(component.purlPrefix());
        return component;
    }

    /**
     * Whether the prefix ends on a boundary {@link #names} expects after it — refused when declared, kept
     * readable when stored so a line bound before the refusal still says why it matched nothing.
     */
    boolean endsOnSeparator() {
        return endsOnSeparator(purlPrefix);
    }

    /**
     * Whether the SBOM's stated version is allowed: written here exactly, or — on a Maven package — in
     * one of the ranges written here.
     */
    boolean allows(String version) {
        if (versions.contains(version)) {
            return true;
        }
        if (!maven()) {
            return false;
        }
        return versions.stream().map(MavenVersionRange::read).flatMap(java.util.Optional::stream)
                .anyMatch(range -> range.contains(version));
    }

    private boolean maven() {
        return purlPrefix.startsWith("pkg:maven/");
    }

    /** Whether a component's package URL is this package's. */
    boolean names(String purl) {
        return names(purlPrefix, purl);
    }

    // ------------------------------------------------------------------ a prefix, whatever the rule

    /** The prefix stripped, or a refusal: what {@link ChecklistRule.ComponentPresent} names checks the same way. */
    static String requirePrefix(String purlPrefix) {
        Objects.requireNonNull(purlPrefix, "purlPrefix");
        String prefix = purlPrefix.strip();
        if (!prefix.startsWith("pkg:") || prefix.length() <= 4 || prefix.length() > MAX_PREFIX
                || prefix.chars().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c))
                || prefix.contains("@")) {
            throw new InvalidInputException("A package is named by a package URL without its version, pkg:type/"
                    + "namespace/name, at most " + MAX_PREFIX + " characters; \"" + BoundedText.clip(prefix, 60)
                    + "\" is not one.");
        }
        return prefix;
    }

    /** The refusal {@link #declared} explains, for any rule a person binds with a prefix. */
    static void refuseEndingOnSeparator(String prefix) {
        if (endsOnSeparator(prefix)) {
            String trimmed = prefix.substring(0, prefix.length() - 1);
            throw new InvalidInputException("A package-URL prefix stops before the separator, never on it: \""
                    + BoundedText.clip(prefix, 60) + "\" names no package. Write \"" + BoundedText.clip(trimmed, 60)
                    + "\" for every package it continues with /, @, ? or # — a namespace's packages — or name one"
                    + " package in full.");
        }
    }

    static boolean endsOnSeparator(String prefix) {
        char last = prefix.charAt(prefix.length() - 1);
        return last == '/' || last == '?' || last == '#';
    }

    static boolean names(String prefix, String purl) {
        if (purl == null || !purl.startsWith(prefix)) {
            return false;
        }
        if (purl.length() == prefix.length()) {
            return true;
        }
        char next = purl.charAt(prefix.length());
        return next == '@' || next == '/' || next == '?' || next == '#';
    }
}

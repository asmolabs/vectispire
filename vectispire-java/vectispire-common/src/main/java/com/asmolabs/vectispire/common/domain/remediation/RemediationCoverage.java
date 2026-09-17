package com.asmolabs.vectispire.common.domain.remediation;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * What the remediation plan can reach, and what it cannot.
 *
 * <h2>Why a remediation screen must denounce itself</h2>
 *
 * <p><b>The ranking looks only at vulnerabilities carrying a package name.</b> That is deliberate
 * and it is right: a line of the plan is a version bump, and a version bump is the only thing that
 * closes fourteen findings at once. But the consequence shows nowhere — a repository whose debt is
 * made of exposed secrets displays a single action against hundreds of open findings, and nothing
 * on the screen says this is not a calculation error.
 *
 * <p>That is exactly the reading a user took from it. The product was right and looked broken,
 * which costs more than a wrong number: a wrong number gets corrected, mistrust is kept. <b>This
 * model is therefore the plan's admission, computed rather than written</b> — it counts the
 * findings the ranking leaves out and says which family they belong to, so the screen can say how
 * they are closed otherwise.
 *
 * <h2>What is not counted here</h2>
 *
 * <p>{@link FindingType#AI_REVIEW} is left out of the total as it is out of the effort estimate:
 * its severity is invented by a local model reading a repository that may be hostile. Including it
 * in "what is left to do" would let a repository inflate its own backlog.
 *
 * <h2>Findings, not distinct vulnerabilities</h2>
 *
 * <p><b>Everything counted here is an open finding</b>, whereas a line of the plan announces
 * distinct identifiers — the same CVE on two repositories is one version bump and two findings.
 * {@link #addressableByUpgrade} therefore does not add up to {@code sum(cveCountResolved)}, and
 * that is intended: the question this model answers is "how many lines of my backlog can this plan
 * close", which is asked in findings.
 */
public record RemediationCoverage(
        long openFindings,
        long addressableByUpgrade,
        long beyondUpgrades,
        List<RemediationGap> gaps) {

    /**
     * The family of vulnerabilities that no package names.
     *
     * <p>A vulnerability without a package is a vulnerability all the same, and yet there is
     * nothing to bump: the scanner reported it on a target without saying which component it comes
     * from. It therefore has a family of its own rather than being diluted into
     * {@code vulnerability}, where it would suggest the plan had merely ranked it too low.
     */
    public static final String UNPACKAGED = "unpackaged";

    /**
     * One open family, as the database counts it.
     *
     * @param type the type's wire name, as the row carries it. <b>Compared to the letter and not
     *     translated into {@link FindingType}</b>: the plan's ranking filters on the exact
     *     {@code vulnerability} string, and a type unknown to this version that were defaulted in
     *     among the vulnerabilities would be announced as covered by a plan that does not look at
     *     it. Unknown, it therefore becomes a gap carrying its own token — the screen will name it
     *     for want of better, and it will be counted
     * @param packageNamed how many of those findings carry a package name
     * @param unnamed how many do not
     */
    public record OpenFamily(String type, long packageNamed, long unnamed) {}

    /**
     * Splits the open families between what a version bump closes and the rest.
     *
     * <p>The gaps are returned from the most numerous to the least, ties broken by name: a screen
     * that names the largest family first answers "why a single line" in its opening sentence, and
     * two readings of the same data agree.
     */
    public static RemediationCoverage of(List<OpenFamily> families) {
        long addressable = 0;
        long beyond = 0;
        List<RemediationGap> gaps = new ArrayList<>();

        for (OpenFamily family : families) {
            if (FindingType.AI_REVIEW.wireName().equals(family.type())) {
                continue;
            }
            if (FindingType.VULNERABILITY.wireName().equals(family.type())) {
                addressable += family.packageNamed();
                if (family.unnamed() > 0) {
                    beyond += family.unnamed();
                    gaps.add(new RemediationGap(UNPACKAGED, family.unnamed()));
                }
                continue;
            }
            long all = family.packageNamed() + family.unnamed();
            if (all > 0) {
                beyond += all;
                gaps.add(new RemediationGap(family.type(), all));
            }
        }

        gaps.sort(Comparator.comparingLong(RemediationGap::findings).reversed()
                .thenComparing(RemediationGap::family));

        return new RemediationCoverage(addressable + beyond, addressable, beyond, List.copyOf(gaps));
    }
}

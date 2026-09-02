package com.asmolabs.vectispire.common.domain.users;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The vocabulary of roles.
 *
 * <p>In the domain and not on the entity: it is a business rule, not a column. The roles would
 * still exist if Vectispire changed database.
 *
 * <p>{@link #isAdministrative()} travels with the constant rather than living in a second
 * {@code ADMIN_ROLES} list. Two lists over one set can disagree, and the disagreement here
 * grants or withholds administration.
 */
public enum Role {
    /**
     * <b>Governs the platform, and operates nothing.</b> See {@link #governsPlatform()} — it is the
     * only role that may change the two settings defining the rules, and the only administrative
     * one that may neither triage nor approve.
     */
    SUPERUSER(true, true, false, true, false, true),
    ADMIN(true, true, true, true, true, false),
    CISO(false, true, true, true, true, false),
    SECURITY_CHAMPION(false, false, true, false, true, false),
    AUDITOR(false, true, false, false, false, false),
    USER(false, false, false, false, true, false);

    private final boolean administrative;
    private final boolean globalSecurityScope;
    private final boolean canApproveTriage;
    private final boolean canWriteGovernance;
    private final boolean canCauseEffects;
    private final boolean governsPlatform;

    Role(
            boolean administrative,
            boolean globalSecurityScope,
            boolean canApproveTriage,
            boolean canWriteGovernance,
            boolean canCauseEffects,
            boolean governsPlatform) {
        this.administrative = administrative;
        this.globalSecurityScope = globalSecurityScope;
        this.canApproveTriage = canApproveTriage;
        this.canWriteGovernance = canWriteGovernance;
        this.canCauseEffects = canCauseEffects;
        this.governsPlatform = governsPlatform;
    }

    public boolean isAdministrative() {
        return administrative;
    }

    /**
     * Sees the whole estate without being assigned to any of it — <b>and may read its governance</b>.
     *
     * <p>The two travel together on purpose. Reading the audit log, the compliance evidence or the
     * gate policy tells you the security posture of every target there is; granting that to an
     * account whose visibility is a handful of repositories would be a way around the scope, not a
     * lesser privilege than it.
     */
    public boolean hasGlobalSecurityScope() {
        return globalSecurityScope;
    }

    /**
     * May <b>change</b> what governance says — the gate policy, the rule sets, the SIEM
     * destination, the licence policy.
     *
     * <p><b>Separated from reading it because {@link #AUDITOR} exists.</b> Until this flag, the two
     * were one privilege and the marker on those routes sat at class level, so somebody who had to
     * inspect the posture was necessarily somebody who could rewrite it. Whoever is asked to check
     * the work should not be able to change it first.
     */
    public boolean canWriteGovernance() {
        return canWriteGovernance;
    }

    public boolean canApproveTriage() {
        return canApproveTriage;
    }

    /**
     * May do something that leaves a trace — record a triage decision, open a ticket in somebody
     * else's tracker, send a target's findings to a model.
     *
     * <p><b>False for {@link #AUDITOR} alone, and that is the whole content of the flag.</b> The
     * role was added with the sentence "sees the whole estate and changes nothing, anywhere"
     * written into its documentation, and the sentence was not true: triage, ticket creation and
     * the OWASP review all sat behind {@code @RequiresAccount}, so a read-only account could settle
     * an issue, create a GitLab issue, and put a target's finding list on a wire towards a host an
     * operator configured.
     *
     * <p>Distinct from {@link #canWriteGovernance}, which is about the <em>rules</em> — the gate
     * policy, the rule sets, the SIEM destination. This one is about the <em>work</em>: an ordinary
     * account does it every day, and an auditor never does any of it.
     *
     * <p>Distinct from {@link #canApproveTriage} too, and the pair is a two-level model worth
     * stating: recording a decision is one permission, having it settle rather than queue is
     * another. A developer holds the first and not the second; an auditor holds neither.
     */
    public boolean canCauseEffects() {
        return canCauseEffects;
    }

    /**
     * May change the two settings that decide the rules everyone else plays by: who can see which
     * targets, and whether writing off a vulnerability needs a second person.
     *
     * <p><b>True for {@link #SUPERUSER} alone, and it is what finally distinguishes it from
     * {@link #ADMIN}.</b> The two carried identical flags — same powers, two names — so the accounts
     * screen offered an elevation that did not exist and somebody would eventually have built a
     * rule on it.
     *
     * <p><b>It comes with a subtraction, and the subtraction is the point.</b> A governor causes no
     * effects and approves nothing. Four-eyes approval was defeatable by anyone who could both
     * switch it off and triage — disable, settle alone, switch back on, with only an audit entry
     * left behind. Removing the right to approve would not have closed that: with the setting off,
     * {@code IssueTriageService} settles everybody's decision, approver or not. What closes it is
     * breaking the <em>conjunction</em>. The account that can lift the rule cannot act under it, so
     * lifting it buys that account nothing.
     *
     * <p>The cost is deliberate and worth stating: on an installation whose only account is the one
     * the bootstrap created, nobody can triage until a working account is made. That is what a
     * root account is for.
     */
    public boolean governsPlatform() {
        return governsPlatform;
    }

    /**
     * Parses a stored or submitted role. <b>Case-sensitive</b>, unlike most parsing here: a
     * role is written by an administrator into a form with a fixed set of choices, and
     * accepting {@code admin} for {@code ADMIN} would mean accepting whatever else arrives in
     * that field.
     */
    public static Optional<Role> of(String value) {
        return value == null
                ? Optional.empty()
                : Arrays.stream(values()).filter(role -> role.name().equals(value)).findFirst();
    }

    /**
     * The roles that count as administrative.
     *
     * <p>Derived from the flag each role carries rather than listed again: two lists of
     * administrators disagree the day somebody adds a role to one of them, and the half that
     * gets forgotten is always the one used by a check.
     */
    public static List<Role> administrative() {
        return Arrays.stream(values()).filter(Role::isAdministrative).toList();
    }
}

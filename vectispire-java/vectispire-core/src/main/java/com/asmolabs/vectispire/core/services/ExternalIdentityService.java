package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Turning an identity the provider vouched for into an account Vectispire already knows.
 * Also synchronizes team memberships from IdP group claims.
 */
@Service
public class ExternalIdentityService {

    private static final Logger log = LoggerFactory.getLogger(ExternalIdentityService.class);

    private final Users users;
    private final Optional<Teams> teams;
    private final Optional<TeamMembers> teamMembers;
    private final boolean linkPrivileged;

    public ExternalIdentityService(Users users) {
        this(users, Optional.empty(), Optional.empty(), false);
    }

    /**
     * @param linkPrivileged whether an administrative or governing account may be bound on its
     *     first sign-on like any other. Off by default: see {@link #resolve(String, String, Claimed)}
     */
    @Autowired
    public ExternalIdentityService(
            Users users,
            Optional<Teams> teams,
            Optional<TeamMembers> teamMembers,
            @Value("${vectispire.oidc.link-privileged-accounts:false}") boolean linkPrivileged) {
        this.users = users;
        this.teams = teams;
        this.teamMembers = teamMembers;
        this.linkPrivileged = linkPrivileged;
    }

    /**
     * What the provider said about the person, as far as binding an account goes.
     *
     * @param username {@code preferred_username}
     * @param email {@code email}, used only when {@code emailVerified} and no username came
     * @param emailVerified {@code email_verified}; absent reads as false
     */
    public record Claimed(String username, String email, boolean emailVerified) {}

    /** Why a sign-on was refused, as a code the login screen translates. */
    public enum Refusal {
        NO_SUBJECT,
        NO_ACCOUNT,
        ALREADY_LINKED,
        PRIVILEGED,
        NO_USERNAME,
        UNVERIFIED_EMAIL,
        DEACTIVATED,
        NO_IDENTITY;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * Refused, with a code for the screen and a sentence for the audit log.
     *
     * <p>The sentence used to travel in the redirect itself — {@code /login?sso=refused&reason=…} —
     * and the screen displayed whatever that parameter said. A link carrying "Your account is
     * suspended, call +33 …" rendered as Vectispire's own message on Vectispire's own page. Only
     * the code leaves now, and the screen shows its own text for the codes it knows.
     */
    public static class SignInRefusedException extends RuntimeException {
        private final Refusal refusal;

        public SignInRefusedException(Refusal refusal, String message) {
            super(message);
            this.refusal = refusal;
        }

        public Refusal refusal() {
            return refusal;
        }
    }

    /** A username claim alone — what a provider sending no email amounts to. */
    public UserEntity resolve(String subject, String issuer, String claimedName) {
        return resolve(subject, issuer, new Claimed(claimedName, null, false));
    }

    /**
     * The account this identity signs in as.
     *
     * <p>Once bound, the subject is the only thing that matters. The first time, a claim has to be
     * matched to an account, and <b>a claim is whatever the realm lets people write</b>: in a realm
     * with self-registration or editable profiles, anybody can call themselves {@code admin}. So the
     * first binding is held to three rules, each closing a way it was taken:
     *
     * <ul>
     *   <li><b>No unverified email.</b> With no username claim the email was used as the name,
     *       verified or not — an address typed at registration opened the account of that name.
     *   <li><b>The name must be the account's, accent for accent.</b> The lookup follows the
     *       database's collation, and MySQL's default opens {@code admin} for {@code ádmin}: a
     *       different identity, registered to look the same. Only case is forgiven.
     *   <li><b>No privileged account on a claim.</b> An administrative or governing account is not
     *       bound by name unless the operator allows it — {@code vectispire.oidc.link-privileged-accounts},
     *       for a realm where nobody chooses their own username. Otherwise it is linked through
     *       SCIM, which sets the subject from the provider itself.
     * </ul>
     *
     * @param subject the provider's {@code sub}, stable for the life of the account
     * @param issuer which provider vouched for it. Required, and <b>not</b> part of the lookup
     */
    @Transactional
    public UserEntity resolve(String subject, String issuer, Claimed claimed) {
        if (subject == null || subject.isBlank() || issuer == null || issuer.isBlank()) {
            throw new SignInRefusedException(Refusal.NO_SUBJECT, "The identity provider returned no usable subject.");
        }

        Optional<UserEntity> bound = users.findByKeycloakId(subject);
        if (bound.isPresent()) {
            return active(bound.get());
        }

        String name = nameToMatch(claimed);

        UserEntity account = users.findByUsername(name)
                // The collation found it; the name has to agree too.
                .filter(found -> found.getUsername().toLowerCase(Locale.ROOT).equals(name))
                .orElseThrow(() -> {
                    log.warn("Single sign-on refused: no account named \"{}\" ({}).", name, issuer);
                    return new SignInRefusedException(Refusal.NO_ACCOUNT,
                            "No Vectispire account matches this identity. An administrator has to create it first.");
                });

        if (account.getKeycloakId() != null) {
            log.warn("Single sign-on refused: \"{}\" is already bound to another subject.", name);
            throw new SignInRefusedException(Refusal.ALREADY_LINKED,
                    "This account is already linked to a different identity. An administrator has to unlink it.");
        }

        boolean privileged = Role.of(account.getRole())
                .map(role -> role.isAdministrative() || role.governsPlatform())
                .orElse(true);
        if (privileged && !linkPrivileged) {
            log.warn("Single sign-on refused: \"{}\" holds a privileged role and is not bound on a claim ({}).",
                    name, issuer);
            throw new SignInRefusedException(Refusal.PRIVILEGED, "This account holds an administrative role, so it is not linked by name. "
                    + "Sign in with its password, or ask for it to be linked through provisioning.");
        }

        UserEntity allowed = active(account);
        allowed.setKeycloakId(subject);
        return users.save(allowed);
    }

    private static String nameToMatch(Claimed claimed) {
        String username = claimed.username() == null ? "" : claimed.username().trim();
        if (!username.isEmpty()) {
            return username.toLowerCase(Locale.ROOT);
        }
        String email = claimed.email() == null ? "" : claimed.email().trim();
        if (!email.isEmpty() && claimed.emailVerified()) {
            return email.toLowerCase(Locale.ROOT);
        }
        throw email.isEmpty()
                ? new SignInRefusedException(Refusal.NO_USERNAME,
                        "The identity provider returned no username to match an account on.")
                : new SignInRefusedException(Refusal.UNVERIFIED_EMAIL,
                        "The identity provider returned no username, and an email address it has not verified.");
    }

    /**
     * Brings an account's teams into line with what the directory has just said.
     *
     * <p><b>A reconciliation, no longer an addition.</b> This method only ever added: removing
     * somebody from a group in the directory took away neither the team nor the visibility that
     * comes with it. That is the opposite of what delegating means — one delegates precisely so
     * that leaving a group revokes an access — and it made the promise "the directory is
     * authoritative" untenable.
     *
     * <p><b>It touches only its own rows.</b> Reconciling everything would have replaced that
     * defect with a worse one: every sign-in would silently erase the teams an administrator
     * assigned by hand. The origin carried by the membership decides who may remove it; what comes
     * from SCIM or from a human decision stays where it is.
     *
     * <p><b>An empty claim is not a revocation.</b> A misconfigured provider, a forgotten mapper, a
     * token without the claim: an absence of groups reads as a configuration failure and not as
     * "this person is no longer in any team". Removing everything on that basis would cut off
     * everyone's access at the first badly set mapper — the caller in fact calls us only when the
     * claim is present and non-empty, and the guard is repeated here because it protects against a
     * mass revocation.
     */
    @Transactional
    public void syncGroups(UserEntity user, List<String> groupNames) {
        if (groupNames == null || groupNames.isEmpty() || teams.isEmpty() || teamMembers.isEmpty()) {
            return;
        }

        Teams teamsRepo = teams.get();
        TeamMembers membersRepo = teamMembers.get();

        // The teams the claim names and that exist here. A group with no matching team is not an
        // error: an organisation's directory is wider than what this tool tracks.
        Set<Long> claimed = new LinkedHashSet<>();
        for (String groupName : groupNames) {
            if (groupName == null || groupName.isBlank()) continue;
            teamsRepo.findByNameIgnoreCase(groupName.trim())
                    .ifPresent(team -> claimed.add(team.getId()));
        }

        List<TeamMemberEntity> held = membersRepo.findByUserId(user.getId());
        Set<Long> alreadyIn = held.stream().map(m -> m.getId().teamId()).collect(Collectors.toSet());

        for (Long teamId : claimed) {
            if (!alreadyIn.contains(teamId)) {
                membersRepo.save(new TeamMemberEntity(teamId, user.getId(), TeamMemberEntity.Origin.OIDC));
                log.info("OIDC sync: user '{}' joined team {}", user.getUsername(), teamId);
            }
        }

        for (TeamMemberEntity membership : held) {
            if (TeamMemberEntity.Origin.OIDC.equals(membership.getOrigin())
                    && !claimed.contains(membership.getId().teamId())) {
                membersRepo.delete(membership);
                log.info("OIDC sync: user '{}' left team {} — no longer in the claim",
                        user.getUsername(), membership.getId().teamId());
            }
        }
    }

    private static UserEntity active(UserEntity account) {
        if (!account.getIsActive()) {
            throw new SignInRefusedException(Refusal.DEACTIVATED, "This account is deactivated.");
        }
        return account;
    }
}

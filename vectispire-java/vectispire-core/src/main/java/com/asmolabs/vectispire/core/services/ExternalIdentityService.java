package com.asmolabs.vectispire.core.services;

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

    public ExternalIdentityService(Users users) {
        this(users, Optional.empty(), Optional.empty());
    }

    @Autowired
    public ExternalIdentityService(Users users, Optional<Teams> teams, Optional<TeamMembers> teamMembers) {
        this.users = users;
        this.teams = teams;
        this.teamMembers = teamMembers;
    }

    /** Refused with a sentence meant to be shown: the person at the screen has to know why. */
    public static class SignInRefusedException extends RuntimeException {
        public SignInRefusedException(String message) {
            super(message);
        }
    }

    /**
     * @param subject the provider's {@code sub}, stable for the life of the account
     * @param issuer which provider vouched for it. Required, and <b>not</b> part of the lookup
     * @param claimedName the username claim, used <b>only</b> to bind an account the first time
     */
    @Transactional
    public UserEntity resolve(String subject, String issuer, String claimedName) {
        if (subject == null || subject.isBlank() || issuer == null || issuer.isBlank()) {
            throw new SignInRefusedException("The identity provider returned no usable subject.");
        }

        Optional<UserEntity> bound = users.findByKeycloakId(subject);
        if (bound.isPresent()) {
            return active(bound.get());
        }

        String name = claimedName == null ? "" : claimedName.trim().toLowerCase(Locale.ROOT);
        if (name.isEmpty()) {
            throw new SignInRefusedException("The identity provider returned no username to match an account on.");
        }

        UserEntity account = users.findByUsername(name)
                .orElseThrow(() -> {
                    log.warn("Single sign-on refused: no account named \"{}\" ({}).", name, issuer);
                    return new SignInRefusedException(
                            "No Vectispire account matches this identity. An administrator has to create it first.");
                });

        if (account.getKeycloakId() != null) {
            log.warn("Single sign-on refused: \"{}\" is already bound to another subject.", name);
            throw new SignInRefusedException(
                    "This account is already linked to a different identity. An administrator has to unlink it.");
        }

        UserEntity allowed = active(account);
        allowed.setKeycloakId(subject);
        return users.save(allowed);
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
            throw new SignInRefusedException("This account is deactivated.");
        }
        return account;
    }
}

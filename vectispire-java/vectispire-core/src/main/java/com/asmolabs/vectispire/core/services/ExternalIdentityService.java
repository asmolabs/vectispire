package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.core.persistence.TeamEntity;
import com.asmolabs.zanshin.core.persistence.TeamMemberEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.TeamMembers;
import com.asmolabs.zanshin.core.repositories.Teams;
import com.asmolabs.zanshin.core.repositories.Users;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turning an identity the provider vouched for into an account Zanshin already knows.
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
                            "No Zanshin account matches this identity. An administrator has to create it first.");
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
     * Synchronizes user's team memberships based on group claims from the identity provider.
     */
    @Transactional
    public void syncGroups(UserEntity user, List<String> groupNames) {
        if (groupNames == null || groupNames.isEmpty() || teams.isEmpty() || teamMembers.isEmpty()) {
            return;
        }

        Teams teamsRepo = teams.get();
        TeamMembers membersRepo = teamMembers.get();

        for (String groupName : groupNames) {
            if (groupName == null || groupName.isBlank()) continue;
            String cleanName = groupName.trim();
            Optional<TeamEntity> team = teamsRepo.findByNameIgnoreCase(cleanName);
            if (team.isPresent()) {
                TeamMemberEntity.Id id = new TeamMemberEntity.Id(team.get().getId(), user.getId());
                if (!membersRepo.existsById(id)) {
                    membersRepo.save(new TeamMemberEntity(team.get().getId(), user.getId()));
                    log.info("OIDC sync: user '{}' assigned to team '{}'", user.getUsername(), team.get().getName());
                }
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

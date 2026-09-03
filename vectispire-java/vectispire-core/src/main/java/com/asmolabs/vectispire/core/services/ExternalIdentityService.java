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
     * Aligne les équipes d'un compte sur ce que l'annuaire vient de dire.
     *
     * <p><b>Une réconciliation, et plus un ajout.</b> Cette méthode n'ajoutait que : retirer
     * quelqu'un d'un groupe dans l'annuaire ne lui retirait ni l'équipe ni la visibilité qui va
     * avec. C'est l'inverse de ce que déléguer veut dire — on délègue précisément pour qu'un départ
     * de groupe révoque un accès — et cela rendait la promesse « l'annuaire fait autorité »
     * intenable.
     *
     * <p><b>Elle ne touche que ses propres lignes.</b> Réconcilier tout aurait remplacé ce défaut
     * par un pire : chaque connexion effacerait les équipes qu'un administrateur a attribuées à la
     * main, en silence. L'origine portée par l'appartenance décide qui peut la retirer ; ce qui
     * vient de SCIM ou d'une décision humaine reste où il est.
     *
     * <p><b>Une revendication vide n'est pas une révocation.</b> Un fournisseur mal configuré, un
     * mapper oublié, un jeton sans la revendication : l'absence de groupes se lit comme une panne
     * de configuration et non comme « cette personne n'est plus dans aucune équipe ». Retirer tout
     * sur cette base couperait l'accès de tout le monde au premier mapper mal réglé — l'appelant
     * ne nous appelle d'ailleurs que si la revendication est présente et non vide, et cette garde
     * est répétée ici parce qu'elle protège d'une révocation de masse.
     */
    @Transactional
    public void syncGroups(UserEntity user, List<String> groupNames) {
        if (groupNames == null || groupNames.isEmpty() || teams.isEmpty() || teamMembers.isEmpty()) {
            return;
        }

        Teams teamsRepo = teams.get();
        TeamMembers membersRepo = teamMembers.get();

        // Les équipes que la revendication nomme et qui existent ici. Un groupe sans équipe
        // correspondante n'est pas une erreur : l'annuaire d'une organisation est plus large que
        // ce que cet outil suit.
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

package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.Users;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turning an identity the provider vouched for into an account Zanshin already knows.
 *
 * <h2>No account is created here</h2>
 *
 * <p><b>Single sign-on says who somebody is; it does not say they may come in.</b> An unknown
 * subject is refused, and an administrator creates the account first. The friendlier reading —
 * provision on first login with the lowest role — is the wrong default for a tool whose backlog
 * names a company's unfixed vulnerabilities: whoever can obtain a token from the realm would
 * obtain a reader's view of every target, and the realm is usually shared with applications that
 * have nothing to do with security.
 *
 * <h2>Bound once by name, matched for ever by subject</h2>
 *
 * <p>The administrator creates an account by username, which is the only thing they can be
 * expected to know — an opaque `sub` is not something anybody types. So the first sign-on binds:
 * it finds the account whose username matches the configured claim, records the subject on it,
 * and every later sign-on matches on that subject alone.
 *
 * <p><b>The two directions are not symmetrical, and the asymmetry is the safety.</b> Matching by
 * name for ever would hand a renamed person somebody else's account the day an address is
 * reassigned. Matching by subject only, from the start, would leave no way to link the account
 * an administrator prepared.
 *
 * <h2>One issuer, and what that costs</h2>
 *
 * <p>The subject is stored in {@code t_user.keycloak_id} — a unique column that predates this by
 * a whole implementation and that nothing ever wrote. Reusing it avoids a second mechanism
 * beside the one already modelled, and avoids adding a column to {@code t_user}: four tables
 * reference that one, and on SQLite an added column makes Liquibase recreate it through a
 * temporary copy, leaving all four pointing at a table that no longer exists.
 *
 * <p><b>The price is that a stored subject is not qualified by its issuer.</b> A {@code sub} is
 * unique within an issuer and means nothing across two, so <b>repointing a deployment at a
 * different realm requires clearing the bindings first</b> — otherwise a stranger sharing an
 * opaque identifier would be matched to an account. The issuer is still passed in and checked
 * for presence, because a provider that returns none is a provider to refuse; it is not part of
 * the lookup, and that is a limitation rather than a design.
 */
@Service
public class ExternalIdentityService {

    private static final Logger log = LoggerFactory.getLogger(ExternalIdentityService.class);

    private final Users users;

    public ExternalIdentityService(Users users) {
        this.users = users;
    }

    /** Refused with a sentence meant to be shown: the person at the screen has to know why. */
    public static class SignInRefusedException extends RuntimeException {
        public SignInRefusedException(String message) {
            super(message);
        }
    }

    /**
     * @param subject the provider's {@code sub}, stable for the life of the account
     * @param issuer which provider vouched for it. Required, and <b>not</b> part of the lookup —
     *     see the note on the class about repointing a deployment at another realm
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
                    // Logged, because the person at the screen is told only that they have no
                    // account — the alternative confirms which usernames exist to anyone holding
                    // a token from the realm.
                    log.warn("Single sign-on refused: no account named \"{}\" ({}).", name, issuer);
                    return new SignInRefusedException(
                            "No Zanshin account matches this identity. An administrator has to create it first.");
                });

        if (account.getKeycloakId() != null) {
            // The account is already bound to a different subject at this issuer. Two people are
            // claiming one username, and guessing which is right is exactly what must not happen
            // quietly.
            log.warn("Single sign-on refused: \"{}\" is already bound to another subject.", name);
            throw new SignInRefusedException(
                    "This account is already linked to a different identity. An administrator has to unlink it.");
        }

        UserEntity allowed = active(account);
        allowed.setKeycloakId(subject);
        return users.save(allowed);
    }

    /**
     * <b>Checked here as well as at the provider.</b> Deactivating somebody in Zanshin has to
     * keep them out even when the realm still happily issues them a token — otherwise "disable
     * this account" means nothing for the accounts that sign in through the provider, which are
     * all of them once single sign-on is on.
     */
    private static UserEntity active(UserEntity account) {
        if (!account.getIsActive()) {
            throw new SignInRefusedException("This account is deactivated.");
        }
        return account;
    }
}

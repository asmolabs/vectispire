package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The first account, created at startup when the users table is empty.
 *
 * <p><b>There is no self-registration page</b>, deliberately: a security application that lets
 * anyone create an administrator account is not one. A path is therefore needed for the very
 * first account, and this is it.
 *
 * <p><b>Documented from the start, implemented nowhere.</b> The README, the getting-started
 * guide and the environment variables all described the bootstrap credentials; nothing read
 * them. A fresh install therefore started with no way to log in — found by standing a control
 * plane up to exercise the remote agent, not by a test.
 *
 * <p><b>Only on an empty table.</b> The settings are ignored as soon as an account exists:
 * without that condition they would be a permanent back door, re-armable by restarting the
 * process with the right variable set.
 *
 * <p><b>That same condition is the only reliable "this install is new".</b> An empty users table
 * is the one moment at which a safe default cannot break anything, because nothing has been
 * configured against the permissive one — so {@link FirstInstallDefaults} is called from here
 * rather than from a listener of its own. Two beans each deciding for themselves whether the
 * database is fresh would race the account creation below and get opposite answers depending on
 * which {@code ApplicationReadyEvent} listener Spring happened to run first.
 */
@Service
public class BootstrapService {

    private static final Logger log = LoggerFactory.getLogger(BootstrapService.class);

    private final Users users;
    private final BootstrapProperties properties;
    private final FirstInstallDefaults firstInstallDefaults;
    private final Clock clock;

    public BootstrapService(
            Users users,
            BootstrapProperties properties,
            FirstInstallDefaults firstInstallDefaults,
            Clock clock) {
        this.users = users;
        this.properties = properties;
        this.firstInstallDefaults = firstInstallDefaults;
        this.clock = clock;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        createFirstUser();
    }

    /** The account created, or empty when there was nothing to do. */
    @Transactional
    public Optional<UserEntity> createFirstUser() {
        if (users.count() > 0) {
            return Optional.empty();
        }

        // **Before every return below, not after the account is created.** A fresh install whose
        // bootstrap credentials are unset or refused is still a fresh install, and it is the one
        // that most needs the safe value: it will be configured by hand later, by somebody who
        // never saw a release note about visibility.
        firstInstallDefaults.apply();

        String username = properties.username().map(String::trim).orElse("");
        String password = properties.password().orElse("");

        if (username.isEmpty() || password.isEmpty()) {
            // Warned and not fatal: a deployment may create its first account some other way.
            // But silence would be worse than anything — the operator would discover the problem
            // in front of a login screen no credentials get through.
            log.warn(
                    "No account exists and no bootstrap credentials are configured: nobody will be able to log in. "
                            + "Set VECTISPIRE_BOOTSTRAP_USERNAME and VECTISPIRE_BOOTSTRAP_PASSWORD, then restart.");
            return Optional.empty();
        }

        Optional<String> refusal = AccountRules.validateUsername(username)
                .or(() -> AccountRules.validatePassword(password));
        if (refusal.isPresent()) {
            log.error("The bootstrap account was not created: {} A first account is a SUPERUSER, "
                    + "and it opens everything else.", refusal.get());
            return Optional.empty();
        }

        Instant moment = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPassword(PasswordHasher.hash(password));
        user.setRole(Role.SUPERUSER.name());
        user.setIsActive(true);
        user.setCreatedAt(moment);
        user.setUpdatedAt(moment);
        // **The password arrives through configuration** — an environment file, an
        // orchestrator's logs, a shell history. Requiring a change at first login is what stops
        // that value remaining the secret of a SUPERUSER account.
        user.setMustChangePassword(true);

        UserEntity created = users.save(user);
        log.info("SUPERUSER account \"{}\" created — password change required at first login.", username);
        return Optional.of(created);
    }
}

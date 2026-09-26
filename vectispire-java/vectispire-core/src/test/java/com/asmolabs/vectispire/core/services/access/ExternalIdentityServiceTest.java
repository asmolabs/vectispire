package com.asmolabs.vectispire.core.services.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Who single sign-on lets in.
 *
 * <p>Against a database rather than a mock: the rules here are about uniqueness and about rows
 * that already exist, and both read correct against a fake.
 */
@DisplayName("resolving an external identity")
class ExternalIdentityServiceTest extends VectispireContextTest {

    private static final String ISSUER = "https://keycloak.example.com/realms/vectispire";

    @Autowired
    private ExternalIdentityService identities;

    @Autowired
    private Users users;

    @BeforeEach
    void emptyDirectory() {
        users.deleteAll();
    }

    @Test
    @DisplayName("an unknown identity is refused, because sign-on is not authorization")
    void anUnknownIdentityIsRefused() {
        // Provisioning on first sign-on is the friendly reading and the wrong default here:
        // whoever can obtain a token from the realm would obtain a reader's view of every
        // target, and the realm is usually shared with applications that have nothing to do
        // with security.
        assertThatThrownBy(() -> identities.resolve("sub-1", ISSUER, "alice"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .hasMessageContaining("An administrator has to create it first");

        assertThat(users.count()).isZero();
    }

    @Test
    @DisplayName("the first sign-on binds the account an administrator prepared")
    void theFirstSignOnBinds() {
        account("alice");

        UserView resolved = identities.resolve("sub-1", ISSUER, "alice");

        assertThat(resolved.username()).isEqualTo("alice");
        assertThat(users.findByKeycloakId("sub-1")).isPresent();
    }

    @Test
    @DisplayName("afterwards the subject is what matches, so a rename changes nothing")
    void theSubjectIsWhatMatches() {
        UserEntity alice = account("alice");
        identities.resolve("sub-1", ISSUER, "alice");

        // Renamed in the directory, and in Vectispire. Keyed on the name this would be a stranger —
        // or, if the old name were reassigned, somebody else's account.
        alice.setUsername("alice.martin");
        users.save(alice);

        assertThat(identities.resolve("sub-1", ISSUER, "alice.martin").id()).isEqualTo(alice.getId());
    }

    @Test
    @DisplayName("a second subject claiming a bound account is refused, not guessed at")
    void aSecondSubjectIsRefused() {
        account("alice");
        identities.resolve("sub-1", ISSUER, "alice");

        // Two people claiming one username. Which is right is not something to decide quietly.
        assertThatThrownBy(() -> identities.resolve("sub-2", ISSUER, "alice"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .hasMessageContaining("already linked");
    }

    @Test
    @DisplayName("a deactivated account stays out, whatever the realm says")
    void aDeactivatedAccountIsRefused() {
        UserEntity alice = account("alice");
        identities.resolve("sub-1", ISSUER, "alice");
        alice.setIsActive(false);
        users.save(alice);

        // Otherwise "disable this account" would mean nothing for the accounts that sign in
        // through the provider — which is all of them, once single sign-on is on.
        assertThatThrownBy(() -> identities.resolve("sub-1", ISSUER, "alice"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .hasMessageContaining("deactivated");
    }

    @Test
    @DisplayName("a provider that returns no subject is refused rather than matched on the name")
    void noSubjectNoSignIn() {
        account("alice");

        assertThatThrownBy(() -> identities.resolve("  ", ISSUER, "alice"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class);
        assertThat(users.findByKeycloakId("  ")).isEmpty();
    }

    @Test
    @DisplayName("an email is matched only when the provider has verified it")
    void anUnverifiedEmailOpensNothing() {
        // With no username claim the email was the name, verified or not: an address typed at
        // registration opened the account of that name.
        account("alice@example.com");

        assertThatThrownBy(() -> identities.resolve(
                        "sub-1", ISSUER, new ExternalIdentityService.Claimed(null, "alice@example.com", false)))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .hasMessageContaining("not verified");
        assertThat(users.findByKeycloakId("sub-1")).isEmpty();

        assertThat(identities.resolve("sub-1", ISSUER, new ExternalIdentityService.Claimed(null, "alice@example.com", true))
                        .username())
                .isEqualTo("alice@example.com");
    }

    @Test
    @DisplayName("a privileged account is not bound on a claim, unless the operator allows it")
    void aPrivilegedAccountIsNotBoundByName() {
        // In a realm with self-registration, anyone can call themselves "admin" — and the
        // bootstrap SUPERUSER is exactly the unbound account that name opened.
        UserEntity admin = account("admin", Role.SUPERUSER);

        assertThatThrownBy(() -> identities.resolve("sub-evil", ISSUER, "admin"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .hasMessageContaining("administrative role")
                // A code for the login screen, which shows its own words: the sentence used to
                // travel in the redirect and be displayed verbatim.
                .extracting(e -> ((ExternalIdentityService.SignInRefusedException) e).refusal())
                .isEqualTo(ExternalIdentityService.Refusal.PRIVILEGED);
        assertThat(users.findById(admin.getId()).orElseThrow().getKeycloakId()).isNull();

        ExternalIdentityService trusting =
                new ExternalIdentityService(users, java.util.Optional.empty(), java.util.Optional.empty(), true);
        assertThat(trusting.resolve("sub-admin", ISSUER, "admin").keycloakId()).isEqualTo("sub-admin");
    }

    @Test
    @DisplayName("a name the collation confuses with an account's is not that account")
    void theCollationDoesNotChooseTheAccount() {
        // MySQL's default collation answers `admin` for `ádmin`. SQLite does not, so the database
        // is stood in for: what is under test is that the service checks the name it was given.
        UserEntity alice = new UserEntity();
        alice.setId(7L);
        alice.setUsername("alice");
        alice.setRole(Role.USER.name());
        alice.setIsActive(true);
        Users accentBlind = org.mockito.Mockito.mock(Users.class);
        org.mockito.Mockito.when(accentBlind.findByKeycloakId("sub-1")).thenReturn(java.util.Optional.empty());
        org.mockito.Mockito.when(accentBlind.findByUsername("álice")).thenReturn(java.util.Optional.of(alice));

        assertThatThrownBy(() -> new ExternalIdentityService(accentBlind).resolve("sub-1", ISSUER, "Álice"))
                .isInstanceOf(ExternalIdentityService.SignInRefusedException.class)
                .hasMessageContaining("No Vectispire account matches");
        org.mockito.Mockito.verify(accentBlind, org.mockito.Mockito.never()).save(org.mockito.ArgumentMatchers.any());
    }

    private UserEntity account(String username) {
        return account(username, Role.USER);
    }

    private UserEntity account(String username, Role role) {
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setDisplayName(username);
        user.setRole(role.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        return users.save(user);
    }
}

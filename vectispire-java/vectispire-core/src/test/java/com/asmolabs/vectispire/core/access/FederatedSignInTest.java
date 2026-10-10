package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.AuthenticationFlowService.FederatedIdentity;
import com.asmolabs.vectispire.core.access.AuthenticationFlowService.FederatedSignIn;
import com.asmolabs.vectispire.core.access.persistence.MfaChallengeRepository;
import com.asmolabs.vectispire.core.access.persistence.SessionRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A single sign-on, from the provider's word to the session, on a real database.
 *
 * <p>The success handler used to orchestrate it — second factor, binding, teams, session, audit —
 * each step committing on its own. What the HTTP adapter cannot show, and the Keycloak campaign
 * would only show by accident, is what the flow leaves behind when one step fails: that is what
 * these cases are for.
 */
@DisplayName("a federated sign-in")
class FederatedSignInTest extends VectispireContextTest {

    private static final String ISSUER = "https://idp.example.invalid/realms/vectispire";

    @Autowired private AuthenticationFlowService flows;
    @Autowired private SignInMethodPolicy methods;
    @Autowired private AuthService auth;
    @Autowired private AuditLogService auditLog;
    @Autowired private TotpService totp;
    @Autowired private UserRepository users;
    @Autowired private SessionRepository sessions;
    @Autowired private MfaChallengeRepository challenges;
    @Autowired private ExternalIdentityService identities;
    @Autowired private TransactionTemplate transactions;
    @Autowired private Clock clock;
    @Autowired private TeamRepository teams;
    @Autowired private TeamMemberRepository members;
    @Autowired private AuditLogRepository audit;

    /** The service as the context builds it, but with the parts a case needs to replace. */
    private AuthenticationFlowService flowsWith(AuthService auth, FederatedSecondFactorPolicy secondFactors) {
        return new AuthenticationFlowService(
                Optional.empty(), methods, auth, auditLog, totp, users, sessions,
                org.mockito.Mockito.mock(com.asmolabs.vectispire.core.access.internal.AccountAdminService.class),
                challenges, identities,
                secondFactors, transactions, clock);
    }

    private static FederatedSecondFactorPolicy mfa(boolean required) {
        return new FederatedSecondFactorPolicy(required, "mfa,otp,hwk,fido", "");
    }

    private static FederatedIdentity alice(List<String> amr, List<String> groups) {
        return new FederatedIdentity(
                "subject-alice", ISSUER, new ExternalIdentityService.Claimed("alice", null, false), amr, null, groups);
    }

    @Test
    @DisplayName("binds the account, joins its claimed teams, opens a session and audits after, naming the second factor")
    void signsIn() {
        UserEntity alice = account("alice");
        long red = team("red");

        FederatedSignIn outcome = flows.completeFederatedSignIn(alice(List.of("otp"), List.of("red")), "probe", "198.51.100.7");

        assertThat(outcome).isInstanceOfSatisfying(FederatedSignIn.SignedIn.class, signedIn -> {
            assertThat(signedIn.user().username()).isEqualTo("alice");
            assertThat(signedIn.issued().token()).isNotBlank();
            assertThat(sessions.findById(signedIn.issued().session().tokenHash()))
                    .hasValueSatisfying(session -> assertThat(session.getIpAddress()).isEqualTo("198.51.100.7"));
        });
        assertThat(users.findById(alice.getId()).orElseThrow().getKeycloakId()).isEqualTo("subject-alice");
        assertThat(members.findByUserId(alice.getId())).singleElement()
                .satisfies(membership -> assertThat(membership.getId().teamId()).isEqualTo(red));
        assertThat(audit.findAllByOrderByTimestampAscIdAsc()).singleElement().satisfies(entry -> {
            assertThat(entry.getOperationType()).isEqualTo(AuditOperation.LOGIN_SUCCESS.name());
            assertThat(entry.getUserId()).isEqualTo("alice");
            assertThat(entry.getIpAddress()).isEqualTo("198.51.100.7");
            assertThat(entry.getDescription())
                    .isEqualTo("Signed in through " + ISSUER + ", second factor stated by the provider (amr=otp)");
        });
    }

    @Test
    @DisplayName("a session that fails to open leaves no binding and no team behind")
    void isAtomic() {
        UserEntity alice = account("alice");
        team("red");
        AuthService failing = mock(AuthService.class);
        doThrow(new IllegalStateException("the insert was refused"))
                .when(failing).openHandoff(any(), any(), any());

        assertThatThrownBy(() -> flowsWith(failing, mfa(false))
                        .completeFederatedSignIn(alice(List.of("otp"), List.of("red")), "probe", "198.51.100.7"))
                .hasMessage("the insert was refused");

        // Bound in a transaction of its own, the subject stayed on the account for a person who
        // was never signed in, and their teams were already reconciled.
        assertThat(users.findById(alice.getId()).orElseThrow().getKeycloakId()).isNull();
        assertThat(members.findByUserId(alice.getId())).isEmpty();
        assertThat(sessions.count()).isZero();
    }

    @Test
    @DisplayName("a deployment requiring a second factor refuses a token that states none before binding anything")
    void theSecondFactorComesFirst() {
        UserEntity alice = account("alice");

        FederatedSignIn outcome = flowsWith(auth, mfa(true))
                .completeFederatedSignIn(alice(List.of("pwd"), null), "probe", "198.51.100.7");

        assertThat(outcome).isEqualTo(new FederatedSignIn.Refused(ExternalIdentityService.Refusal.MFA_REQUIRED));
        assertThat(users.findById(alice.getId()).orElseThrow().getKeycloakId()).isNull();
        assertThat(sessions.count()).isZero();
        assertThat(audit.findAllByOrderByTimestampAscIdAsc()).singleElement().satisfies(entry -> {
            assertThat(entry.getOperationType()).isEqualTo(AuditOperation.LOGIN_FAILURE.name());
            assertThat(entry.getResourceId()).isEqualTo("subject-alice");
            assertThat(entry.getUserId()).isNull();
            assertThat(entry.getDescription()).startsWith("Single sign-on refused: ");
        });
    }

    @Test
    @DisplayName("a privileged account is not bound on a claim, and the refusal is audited")
    void aPrivilegedAccountIsRefused() {
        UserEntity admin = account("alice");
        admin.setRole(Role.ADMIN.name());
        users.save(admin);

        FederatedSignIn outcome = flows.completeFederatedSignIn(alice(List.of("otp"), null), "probe", "198.51.100.7");

        assertThat(outcome).isEqualTo(new FederatedSignIn.Refused(ExternalIdentityService.Refusal.PRIVILEGED));
        assertThat(users.findById(admin.getId()).orElseThrow().getKeycloakId()).isNull();
        assertThat(sessions.count()).isZero();
        assertThat(audit.findAllByOrderByTimestampAscIdAsc()).singleElement()
                .satisfies(entry -> assertThat(entry.getOperationType()).isEqualTo(AuditOperation.LOGIN_FAILURE.name()));
    }

    private UserEntity account(String username) {
        Instant now = Instant.now();
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPassword("unused");
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setMfaEnabled(false);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return users.save(user);
    }

    private long team(String name) {
        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setCreatedAt(Instant.now());
        return teams.save(team).getId();
    }
}

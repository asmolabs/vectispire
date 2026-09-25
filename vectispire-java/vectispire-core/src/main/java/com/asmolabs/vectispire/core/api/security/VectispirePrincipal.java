package com.asmolabs.vectispire.core.api.security;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.ApiKeyAuthService;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Who is making this request: a person with a session, or an agent with an API key.
 *
 * <p><b>Two authentications, one type.</b> They are genuinely different — an agent has no
 * session, no role and no password to change — and modelling them as two token classes would
 * mean every filter and every controller asking "which kind is this" before it can do
 * anything. One token that can answer both questions keeps that branch in one place.
 */
public final class VectispirePrincipal extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    /** The authority prefix Spring Security expects on a role. */
    static final String ROLE_PREFIX = "ROLE_";

    private final transient UserEntity user;
    private final transient SessionEntity session;
    private final transient AgentEntity agent;

    /**
     * The narrowing the credential itself carries.
     *
     * <p>A session answers everything and leaves the narrowing to the account; an agent key is
     * issued unrestricted; an integration key carries the target it was restricted to (decision
     * 0024). Every read route passes it, so the key's narrowing is intersected everywhere at once
     * instead of route by route.
     *
     * <p>On the principal rather than fetched by whoever needs it, because "whoever needs it" is
     * every read route and one of them would eventually not. It arrives already resolved from
     * the filter that authenticated the request.
     */
    private final transient Visibility credentialRestriction;

    /** The integration key the request came with, when it came with one (decision 0024). */
    private final transient ApiKeyAuthService.Integration integration;

    private VectispirePrincipal(
            UserEntity user,
            SessionEntity session,
            AgentEntity agent,
            Visibility credentialRestriction,
            Collection<? extends GrantedAuthority> authorities) {
        this(user, session, agent, credentialRestriction, authorities, null);
    }

    private VectispirePrincipal(
            UserEntity user,
            SessionEntity session,
            AgentEntity agent,
            Visibility credentialRestriction,
            Collection<? extends GrantedAuthority> authorities,
            ApiKeyAuthService.Integration integration) {
        super(authorities);
        this.user = user;
        this.session = session;
        this.agent = agent;
        this.credentialRestriction = credentialRestriction;
        this.integration = integration;
        setAuthenticated(true);
    }

    /**
     * An integration key, acting for its account (decision 0024).
     *
     * <p>The account's role is the authority, so the role markers keep deciding what the key may do
     * within the routes that accept a key at all — which {@code CredentialConfinement} decides. No
     * session: nothing about a key belongs to a browser.
     */
    public static VectispirePrincipal ofIntegration(ApiKeyAuthService.Integration integration) {
        Role role = Role.of(integration.owner().getRole()).orElse(null);
        List<GrantedAuthority> authorities = role == null
                ? List.of()
                : List.of(new SimpleGrantedAuthority(ROLE_PREFIX + role.name()));
        return new VectispirePrincipal(
                integration.owner(), null, null, integration.restriction(), authorities, integration);
    }

    public Optional<ApiKeyAuthService.Integration> integration() {
        return Optional.ofNullable(integration);
    }

    public static VectispirePrincipal ofUser(UserEntity user, SessionEntity session) {
        Role role = Role.of(user.getRole()).orElse(null);
        List<GrantedAuthority> authorities = role == null
                // An unreadable role authorizes nothing. Not a fallback to the least privileged
                // role either: that would silently keep an account working after somebody
                // mistyped its role in the database, and nobody would ever look.
                ? List.of()
                : List.of(new SimpleGrantedAuthority(ROLE_PREFIX + role.name()));
        // A session carries no restriction of its own; the account's assignments are
        // resolved separately, and intersected with this.
        return new VectispirePrincipal(user, session, null, Visibility.everything(), authorities);
    }

    public static VectispirePrincipal ofAgent(AgentEntity agent, Visibility credentialRestriction) {
        return new VectispirePrincipal(
                null, null, agent, credentialRestriction, List.of(new SimpleGrantedAuthority("SCOPE_AGENT")));
    }

    public static VectispirePrincipal ofScimClient() {
        return new VectispirePrincipal(
                null,
                null,
                null,
                Visibility.everything(),
                List.of(new SimpleGrantedAuthority(ROLE_PREFIX + Role.ADMIN.name()), new SimpleGrantedAuthority("SCOPE_SCIM")));
    }

    /** What the credential itself allows, before the account's own assignments narrow it further. */
    public Visibility credentialRestriction() {
        return credentialRestriction;
    }

    public Optional<UserEntity> user() {
        return Optional.ofNullable(user);
    }

    public Optional<SessionEntity> session() {
        return Optional.ofNullable(session);
    }

    public Optional<AgentEntity> agent() {
        return Optional.ofNullable(agent);
    }

    /** The signed-in account, or a failure: for the routes where anonymity is already excluded. */
    public UserEntity requireUser() {
        return user().orElseThrow(() -> new IllegalStateException("This route requires a signed-in account."));
    }

    @Override
    public Object getCredentials() {
        // Never the token. A credential that prints itself ends up in a log, then in an
        // exception message, then in a bug report.
        return "";
    }

    /**
     * <b>The token itself, not the row behind it.</b>
     *
     * <p>{@code @AuthenticationPrincipal} injects whatever this returns, and every controller
     * asks for a {@code VectispirePrincipal}. Returning the {@code UserEntity} — the obvious
     * reading of "principal" — made the types disagree, so Spring injected {@code null} into
     * every authenticated route in the application. Nothing failed to compile and no unit test
     * could see it: the first symptom was a NullPointerException on the first real request,
     * found by the first test that made one.
     */
    @Override
    public Object getPrincipal() {
        return this;
    }

    /**
     * The width of the audit log's and the gate register's actor columns. A username alone may
     * already fill it, so the key's name is what gives way first — the account is the authority,
     * and a truncated key name still tells the reader a key was used.
     */
    static final int ACTOR_WIDTH = 255;

    static String attribution(String username, String keyName) {
        String full = username + " (API key " + keyName + ")";
        if (full.length() <= ACTOR_WIDTH) {
            return full;
        }
        String withoutName = username + " (API key …)";
        if (withoutName.length() <= ACTOR_WIDTH) {
            int room = ACTOR_WIDTH - withoutName.length();
            return username + " (API key " + keyName.substring(0, room) + "…)";
        }
        return username.substring(0, ACTOR_WIDTH - " (API key …)".length()) + " (API key …)";
    }

    @Override
    public String getName() {
        if (integration != null) {
            // The account, and the key beside it: every write the key makes is the account's, and
            // the audit entry must still say which credential made it.
            return attribution(user.getUsername(), integration.keyName());
        }
        if (user != null) {
            return user.getUsername();
        }
        return agent != null ? "agent:" + agent.getName() : "anonymous";
    }
}

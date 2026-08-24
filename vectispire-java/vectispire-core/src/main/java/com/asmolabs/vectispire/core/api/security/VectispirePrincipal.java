package com.asmolabs.vectispire.core.api.security;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
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
     * The narrowing the credential itself carries — an API key issued for one target.
     *
     * <p>On the principal rather than fetched by whoever needs it, because "whoever needs it" is
     * every read route and one of them would eventually not. It arrives already resolved from
     * the filter that authenticated the request.
     */
    private final transient Visibility credentialRestriction;

    private VectispirePrincipal(
            UserEntity user,
            SessionEntity session,
            AgentEntity agent,
            Visibility credentialRestriction,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.user = user;
        this.session = session;
        this.agent = agent;
        this.credentialRestriction = credentialRestriction;
        setAuthenticated(true);
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

    @Override
    public String getName() {
        if (user != null) {
            return user.getUsername();
        }
        return agent != null ? "agent:" + agent.getName() : "anonymous";
    }
}

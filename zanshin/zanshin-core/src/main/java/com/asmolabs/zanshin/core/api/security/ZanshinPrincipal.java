package com.asmolabs.zanshin.core.api.security;

import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.persistence.AgentEntity;
import com.asmolabs.zanshin.core.persistence.SessionEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
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
public final class ZanshinPrincipal extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    /** The authority prefix Spring Security expects on a role. */
    static final String ROLE_PREFIX = "ROLE_";

    private final transient UserEntity user;
    private final transient SessionEntity session;
    private final transient AgentEntity agent;

    private ZanshinPrincipal(
            UserEntity user,
            SessionEntity session,
            AgentEntity agent,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.user = user;
        this.session = session;
        this.agent = agent;
        setAuthenticated(true);
    }

    public static ZanshinPrincipal ofUser(UserEntity user, SessionEntity session) {
        Role role = Role.of(user.getRole()).orElse(null);
        List<GrantedAuthority> authorities = role == null
                // An unreadable role authorizes nothing. Not a fallback to the least privileged
                // role either: that would silently keep an account working after somebody
                // mistyped its role in the database, and nobody would ever look.
                ? List.of()
                : List.of(new SimpleGrantedAuthority(ROLE_PREFIX + role.name()));
        return new ZanshinPrincipal(user, session, null, authorities);
    }

    public static ZanshinPrincipal ofAgent(AgentEntity agent) {
        return new ZanshinPrincipal(null, null, agent, List.of(new SimpleGrantedAuthority("SCOPE_AGENT")));
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
     * asks for a {@code ZanshinPrincipal}. Returning the {@code UserEntity} — the obvious
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

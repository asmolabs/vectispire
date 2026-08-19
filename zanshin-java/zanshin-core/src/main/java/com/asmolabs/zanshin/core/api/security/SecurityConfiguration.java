package com.asmolabs.zanshin.core.api.security;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.core.services.AuditLogService;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * The access rules.
 *
 * <p><b>What this replaces.</b> In Reflex, every event handler on a state class was
 * individually addressable over a websocket: a check placed when the page mounted protected the
 * rendering, not the handlers. Hence the decorator on <em>every</em> method touching the
 * database, and the four wrapper variants needed to cover plain functions, coroutines and both
 * kinds of generator. That problem is gone — an HTTP route has one entry point — but the rule
 * it carried is not: <b>authorization applies at the entry point, never at the rendering</b>.
 *
 * <p><b>Stateless, and that is not a detail.</b> Zanshin's session lives in a table, shared by
 * every instance, so a servlet session would be a second notion of "logged in" — one that does
 * not survive a restart and does not cross instances, and that would silently take precedence.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfiguration implements WebMvcConfigurer {

    private final BearerAuthenticationFilter bearer;
    private final PasswordChangeInterceptor passwordChange;
    private final AuditLogService audit;

    public SecurityConfiguration(
            BearerAuthenticationFilter bearer, PasswordChangeInterceptor passwordChange, AuditLogService audit) {
        this.bearer = bearer;
        this.passwordChange = passwordChange;
        this.audit = audit;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(passwordChange);
    }

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
                // No CSRF token: this API is consumed by a client that sends a bearer token, and
                // a bearer token is not attached by a browser to a cross-site request. Enabling
                // it would only break the agent protocol, which has no page to read a token from.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(bearer, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(handling -> handling
                        // 401 with no body and no `WWW-Authenticate` challenge: a browser
                        // prompting for basic credentials over a token API helps nobody.
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler(auditingDeniedHandler()))
                .authorizeHttpRequests(requests -> requests
                        // **The error dispatch is not a request.** When a handler throws, the
                        // container re-dispatches to `/error`, and that dispatch goes through
                        // this chain again — with the security context already cleared. Without
                        // this line every unmapped failure came back as 401 and an empty body:
                        // the client reads "sign in", signs in, fails again, and the real 500 is
                        // never seen by anybody. Found by starting the application and asking it
                        // to do something it refuses.
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers("/api/v1/auth/login").permitAll()
                        // The agent protocol authenticates by API key, resolved by the filter
                        // above; the controller refuses when no agent came out of it.
                        .requestMatchers("/api/v1/agent/**").permitAll()
                        .requestMatchers("/actuator/health/**").permitAll()
                        .anyRequest().authenticated())
                .build();
    }

    /**
     * A refusal is audited, and that is the point of overriding the default handler.
     *
     * <p>An authorization refusal used to be an application log line, so sweeping every endpoint
     * left no trace an operator would ever look at.
     */
    private AccessDeniedHandler auditingDeniedHandler() {
        return (request, response, denied) -> {
            String who = SecurityContextHolder.getContext().getAuthentication() instanceof ZanshinPrincipal principal
                    ? principal.getName()
                    : null;
            audit.record(new AuditLogService.Record(
                    AuditOperation.ACCESS_DENIED,
                    request.getRequestURI(),
                    "Access denied: " + denied.getMessage(),
                    who,
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
            response.sendError(HttpStatus.FORBIDDEN.value());
        };
    }
}

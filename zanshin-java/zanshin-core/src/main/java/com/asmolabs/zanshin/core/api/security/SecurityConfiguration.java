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
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
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

    /**
     * The content security policy, in one place because it is one sentence.
     *
     * <p><b>What it is for.</b> Everything Zanshin displays — a finding's message, a package
     * name, a CVE description, a commit author — comes from the analyzers and the advisory
     * feeds, which is to say from data an attacker influences. This header is what decides
     * whether a string that got through the rendering runs with the analyst's session or sits
     * there inert. It is the last line, not the first: it does not excuse an unescaped
     * interpolation, it survives one.
     *
     * <p><b>Read the relaxations, not the restrictions.</b> `default-src 'self'` already covers
     * scripts, styles, images, fonts and XHR; the directives repeating it are named anyway so
     * that narrowing one later is an edit rather than an addition. Everything below that is a
     * hole, and each one carries what would happen without it:
     *
     * <ul>
     *   <li>{@code object-src 'none'} and {@code base-uri 'self'} are not covered by
     *       {@code default-src} at all. A {@code <base>} tag injected into the document
     *       silently re-points every relative URL on the page — including the API calls — at
     *       somebody else's host, and no other directive says a word about it.
     *   <li>{@code frame-ancestors 'none'} is the modern half of {@code X-Frame-Options}, kept
     *       alongside it because a proxy or a browser may honour one and not the other.
     *   <li>{@code form-action 'self'} stops an injected form from posting the session
     *       elsewhere. There is one real form flow — the OIDC redirect — and it is same-origin.
     * </ul>
     *
     * <p><b>{@code style-src} carries {@code 'unsafe-inline'}, and that was measured rather than
     * assumed.</b> Without it the production bundle loads and runs, and renders completely
     * unstyled: Angular emits component styles as {@code <style>} elements at runtime and
     * PrimeNG sets style attributes on elements it positions, and the console fills with
     * "Applying inline style violates ... style-src 'self'" — several dozen on the sign-in page
     * alone. Neither a nonce nor a hash list fixes it, because the browser applies neither to
     * <em>style attributes</em>; closing this properly is a change to the interface, not to this
     * header.
     *
     * <p>What that costs is worth naming rather than waving at: an injected {@code <style>} can
     * still redress the page — cover a button, fake a dialog, and leak the shape of the DOM
     * through selectors. What it cannot do is execute, because {@code script-src} keeps no
     * {@code 'unsafe-inline'} and no {@code 'unsafe-eval'} — and that is the half that turns a
     * displayed string into a session. A policy relaxed on styles still stops the attack this
     * header exists for; one relaxed on scripts would not.
     *
     * <p><b>No {@code 'unsafe-eval'}, and the Angular build does not need it</b> — that is a
     * property of the production configuration, which compiles templates ahead of time. A
     * development build does eval, which is one more reason the measurement was taken against
     * the bundle that ships.
     *
     * <p><b>HSTS stays absent, deliberately.</b> Zanshin is routinely reached over plain HTTP on
     * an internal address; a Strict-Transport-Security header seen once makes that origin
     * permanently unreachable in that browser. It belongs to the proxy terminating TLS, which is
     * the component that knows it has TLS.
     */
    private static final String CONTENT_SECURITY_POLICY = String.join("; ",
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'");

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
                // On every response, static files included: the document that carries the
                // injected string is `index.html`, so a policy applied only to `/api` would
                // guard the JSON and leave the page it is rendered into unprotected.
                .headers(headers -> headers.contentSecurityPolicy(
                        policy -> policy.policyDirectives(CONTENT_SECURITY_POLICY)))
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
                        // Both are pre-authentication by construction: one says which buttons
                        // the login screen should offer, the other trades a one-time cookie the
                        // browser just received for the session it stands for. Neither can
                        // require the session it is on the way to producing.
                        .requestMatchers("/api/v1/auth/methods").permitAll()
                        .requestMatchers("/api/v1/auth/session/exchange").permitAll()
                        // The agent protocol authenticates by API key, resolved by the filter
                        // above; the controller refuses when no agent came out of it.
                        .requestMatchers("/api/v1/agent/**").permitAll()
                        .requestMatchers("/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/scorecards/repositories/*/badge.svg").permitAll()
                        // **The interface itself is not behind the token.** When the jar
                        // bundles the Angular build, these are the files that *ask* for a
                        // token; requiring one to fetch them means the sign-in screen answers
                        // 401 and nobody can ever sign in. Nothing here is a secret — it is
                        // the same bundle any visitor of a public deployment downloads — and
                        // every API call it then makes is authenticated as before.
                        .requestMatchers(HttpMethod.GET, "/", "/index.html", "/favicon.ico",
                                "/*.js", "/*.css", "/*.webmanifest", "/assets/**", "/fonts/**",
                                "/media/**", "/i18n/**")
                        .permitAll()
                        // **The SPA's deep links, on the request and on the forward.**
                        // `SpaForwarding` sends `/security` to index.html — but the chain runs
                        // first, and `anyRequest().authenticated()` would refuse the request
                        // before any forwarding happened. Both passes therefore need a rule.
                        //
                        // The pattern mirrors that class exactly: a GET whose path is not under
                        // `/api` or `/actuator` and contains no dot. The negative lookahead is
                        // what keeps an unmapped API path a 404 the caller can act on instead
                        // of an HTML page, and the missing dot keeps a lost `.js` a 404 rather
                        // than a document the browser reports as a syntax error.
                        .requestMatchers(RegexRequestMatcher.regexMatcher(
                                HttpMethod.GET, "^/(?!api/|actuator/|scim/)[^.]*$"))
                        .permitAll()
                        .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
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

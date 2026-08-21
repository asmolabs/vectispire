package com.asmolabs.zanshin.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.users.AccountRules;
import com.asmolabs.zanshin.core.api.security.OpenToAnonymous;
import com.asmolabs.zanshin.core.api.security.PasswordChangeGate;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.OidcConfiguration;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.SessionEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.UserSessions;
import com.asmolabs.zanshin.core.repositories.Users;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.util.Optional;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Signing in, signing out, and "who am I".
 *
 * <p>The login screen shows no default credentials and this API returns none: the provisioning
 * account carries {@code mustChangePassword}, which is the right way to say "change your
 * password" without saying what it is.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    /** Absent when no issuer is configured: single sign-on is optional, and absent when off. */
    private final Optional<ClientRegistrationRepository> providers;

    private final AuthService auth;
    private final AuditLogService audit;
    private final Users users;
    private final UserSessions sessions;
    private final Clock clock;

    public AuthController(
            AuthService auth,
            AuditLogService audit,
            Users users,
            UserSessions sessions,
            Optional<ClientRegistrationRepository> providers,
            Clock clock) {
        this.providers = providers;
        this.auth = auth;
        this.audit = audit;
        this.users = users;
        this.sessions = sessions;
        this.clock = clock;
    }

    /** @param clientId the throttle's second counter. Never the IP alone — see {@link AuthService} */
    public record LoginRequest(String username, String password, @JsonProperty("client_id") String clientId) {}

    public record LoginResponse(String token, Instant expiresAt, UserSummary user) {}

    public record UserSummary(String username, String displayName, String role, boolean mustChangePassword) {}

    public record ChangePasswordRequest(@JsonProperty("current_password") String currentPassword, @JsonProperty("new_password") String newPassword) {}

    @OpenToAnonymous
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest body, HttpServletRequest request) {
        AuthService.LoginResult result = auth.login(new AuthService.LoginRequest(
                text(body == null ? null : body.username()),
                text(body == null ? null : body.password()),
                clientId(body, request),
                request.getHeader("User-Agent"),
                request.getRemoteAddr()));

        audit.record(new AuditLogService.Record(
                result.audit().operation(),
                result.audit().resourceId(),
                result.audit().description(),
                result.audit().userId(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return switch (result.outcome()) {
            case AuthService.Outcome.Blocked blocked ->
                // 429 and not 401: the password was never judged, and the caller needs to know
                // it has to wait rather than try again.
                throw new ResponseStatusException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "Too many attempts. Try again in " + blocked.retryAfter().toSeconds() + "s.");
            case AuthService.Outcome.Invalid ignored ->
                // One message for "unknown account" and for "wrong password": telling them apart
                // hands whoever is probing the list of accounts that exist.
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials.");
            case AuthService.Outcome.Success success -> new LoginResponse(
                    // The one moment the clear token exists outside the client: it is not stored,
                    // so it cannot be read back for a second response.
                    success.issued().token(),
                    success.issued().session().getExpiresAt(),
                    summaryOf(success.user()));
        };
    }

    /**
     * @param configured whether an identity provider is wired at all — the screen offers the
     *     button only then, because an optional feature that is off should be absent rather than
     *     present and refusing
     */
    public record SignInMethods(boolean configured, String label) {}

    /**
     * What this deployment accepts as a way in.
     *
     * <p>Readable without a session, on purpose and with nothing sensitive in it: the login
     * screen has to render the right buttons before anybody is authenticated, and "this instance
     * has single sign-on" is not a secret — the redirect it produces is public by construction.
     */
    @OpenToAnonymous
    @GetMapping("/methods")
    public SignInMethods methods() {
        return new SignInMethods(providers.isPresent(), providers.map(this::labelOf).orElse(null));
    }

    /**
     * Exchanges the one-time hand-off cookie for the session token.
     *
     * <p><b>Why a cookie and an exchange rather than a token in the URL.</b> The usual shortcut
     * puts the token in the redirect's fragment, which never reaches a server — and does reach
     * the browser's history, where a session token outlives the tab. The cookie is
     * {@code HttpOnly}, lives sixty seconds, and is deleted here: the application reads it once,
     * through a request the interceptor will carry from then on.
     */
    @OpenToAnonymous
    @PostMapping("/session/exchange")
    public LoginResponse exchange(HttpServletRequest request, HttpServletResponse response) {
        String token = handoffToken(request);
        if (token == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No sign-on to complete.");
        }
        clearHandoff(response, request.isSecure());

        SessionEntity session = auth.resolve("Bearer " + token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "This sign-on has expired."));
        UserEntity user = users.findById(session.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account not found."));

        // The token comes from the cookie, not from the row: the row holds a hash, and handing
        // that back would be handing back something that authenticates nothing.
        return new LoginResponse(token, session.getExpiresAt(), summaryOf(user));
    }

    private static String handoffToken(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (OidcConfiguration.HANDOFF_COOKIE.equals(cookie.getName()) && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /** Deleted whether or not it was usable: a hand-off cookie is worth one attempt. */
    private static void clearHandoff(HttpServletResponse response, boolean secure) {
        Cookie cleared = new Cookie(OidcConfiguration.HANDOFF_COOKIE, "");
        cleared.setHttpOnly(true);
        cleared.setPath("/");
        cleared.setMaxAge(0);
        cleared.setSecure(secure);
        response.addCookie(cleared);
    }

    private String labelOf(ClientRegistrationRepository repository) {
        if (repository instanceof Iterable<?> registrations) {
            for (Object registration : registrations) {
                if (registration instanceof ClientRegistration client) {
                    return client.getClientName();
                }
            }
        }
        return "single sign-on";
    }

    @RequiresAccount
    @PasswordChangeGate
    @DeleteMapping("/session")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal ZanshinPrincipal principal) {
        // The row disappears: signing out is real, including for a tab left open elsewhere.
        principal.session().ifPresent(auth::revoke);
    }

    /**
     * Changes one's own password.
     *
     * <p>The current password is required even when {@code mustChangePassword} is set: without
     * it, a workstation left unlocked for a minute would be enough to take the account. There is
     * no "first login" exemption — the person has just typed that password to get here.
     *
     * <p>The account's <b>other</b> sessions are closed. Changing a password is what one does
     * when one believes it compromised: leaving sessions alive elsewhere would empty the gesture
     * of its meaning. The current session survives, or the screen would bounce back to the login
     * page immediately after succeeding.
     */
    @RequiresAccount
    @PasswordChangeGate
    @PostMapping("/change-password")
    public Map<String, Object> changePassword(
            @RequestBody ChangePasswordRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        UserEntity user = principal.requireUser();
        String current = text(body == null ? null : body.currentPassword());
        String next = text(body == null ? null : body.newPassword());

        if (!PasswordHasher.verify(current, user.getPassword())) {
            // 401 and not 400: what is missing is proof of identity, not a well-formed field,
            // and the screen has to be able to tell the two apart.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Current password is incorrect.");
        }
        AccountRules.validatePassword(next).ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });
        if (next.equals(current)) {
            throw new IllegalArgumentException("The new password is the same as the old one.");
        }

        users.changePassword(user.getId(), PasswordHasher.hash(next), clock.instant());
        principal.session()
                .ifPresent(session -> sessions.deleteByUserIdExcept(user.getId(), session.getTokenHash()));

        audit.record(new AuditLogService.Record(
                AuditOperation.PASSWORD_CHANGED,
                String.valueOf(user.getId()),
                "Password changed by " + user.getUsername(),
                user.getUsername(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("mustChangePassword", false);
    }

    @RequiresAccount
    @PasswordChangeGate
    @GetMapping("/me")
    public ResponseEntity<UserSummary> me(@AuthenticationPrincipal ZanshinPrincipal principal) {
        return ResponseEntity.ok(summaryOf(principal.requireUser()));
    }

    private static UserSummary summaryOf(UserEntity user) {
        return new UserSummary(
                user.getUsername(), user.getDisplayName(), user.getRole(), user.getMustChangePassword());
    }

    private static String clientId(LoginRequest body, HttpServletRequest request) {
        String supplied = text(body == null ? null : body.clientId());
        return supplied.isEmpty() ? String.valueOf(request.getRemoteAddr()) : supplied;
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }
}

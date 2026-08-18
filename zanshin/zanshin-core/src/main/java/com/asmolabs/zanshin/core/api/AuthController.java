package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.users.AccountRules;
import com.asmolabs.zanshin.core.api.security.OpenToAnonymous;
import com.asmolabs.zanshin.core.api.security.PasswordChangeGate;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.UserSessions;
import com.asmolabs.zanshin.core.repositories.Users;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    private final AuthService auth;
    private final AuditLogService audit;
    private final Users users;
    private final UserSessions sessions;
    private final Clock clock;

    public AuthController(
            AuthService auth, AuditLogService audit, Users users, UserSessions sessions, Clock clock) {
        this.auth = auth;
        this.audit = audit;
        this.users = users;
        this.sessions = sessions;
        this.clock = clock;
    }

    /** @param clientId the throttle's second counter. Never the IP alone — see {@link AuthService} */
    public record LoginRequest(String username, String password, String clientId) {}

    public record LoginResponse(String token, Instant expiresAt, UserSummary user) {}

    public record UserSummary(String username, String displayName, String role, boolean mustChangePassword) {}

    public record ChangePasswordRequest(String currentPassword, String newPassword) {}

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
                    success.session().getToken(), success.session().getExpiresAt(), summaryOf(success.user()));
        };
    }

    @RequiresAccount
    @PasswordChangeGate
    @DeleteMapping("/session")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal ZanshinPrincipal principal) {
        // The row disappears: signing out is real, including for a tab left open elsewhere.
        principal.session().ifPresent(session -> auth.revoke(session.getToken()));
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
        principal.session().ifPresent(session -> sessions.deleteByUserIdExcept(user.getId(), session.getToken()));

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

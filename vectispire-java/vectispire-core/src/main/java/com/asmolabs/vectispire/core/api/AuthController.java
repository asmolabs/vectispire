package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.core.api.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.api.security.PasswordChangeGate;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.SignInMethodPolicy;
import com.asmolabs.vectispire.core.api.security.OidcConfiguration;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.AuthService;
import com.asmolabs.vectispire.core.services.TotpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Authentication", description = "User login, MFA, SSO and session management")
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    /** Absent when no issuer is configured: single sign-on is optional, and absent when off. */
    private final Optional<ClientRegistrationRepository> providers;

    private final SignInMethodPolicy methods;
    private final AuthService auth;
    private final AuditLogService audit;
    private final Users users;
    private final UserSessions sessions;
    private final Clock clock;

    private final TotpService totp;
    private final com.asmolabs.vectispire.core.services.BrandingProperties branding;
    private final Map<String, MfaChallenge> mfaChallenges = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * **A TOTP code is six digits, so the number of tries is the whole security of the second
     * factor.** Unlimited tries against a five-minute window is a million-code space explored at
     * whatever rate the server sustains, which is not a second factor — it is a delay. Three,
     * then the challenge is destroyed and the password exchange starts again.
     */
    private static final int MAX_MFA_ATTEMPTS = 3;

    /**
     * A bound on how many challenges may be held at once.
     *
     * <p>Each successful password exchange by an MFA-enabled account leaves one entry, and only
     * a success or a later presentation removes it: an abandoned sign-in leaks the entry until
     * the process restarts. The sweep in {@link #rememberChallenge} clears what has expired, and
     * this cap is what stops the map growing without bound between two sweeps.
     */
    private static final int MAX_MFA_CHALLENGES = 10_000;

    /**
     * @param attempts counted on the challenge rather than on the account: the challenge is what
     *     the attacker holds, and it is what gets destroyed. Mutable inside an otherwise
     *     immutable record so a failure need not race a {@code put} against a concurrent one.
     */
    public record MfaChallenge(
            Long userId,
            Instant expiresAt,
            String userAgent,
            String ipAddress,
            java.util.concurrent.atomic.AtomicInteger attempts) {

        public MfaChallenge(Long userId, Instant expiresAt, String userAgent, String ipAddress) {
            this(userId, expiresAt, userAgent, ipAddress, new java.util.concurrent.atomic.AtomicInteger());
        }
    }

    public record MfaVerifyRequest(@JsonProperty("mfa_token") String mfaToken, String code) {}
    public record MfaEnableRequest(String secret, String code) {}
    public record MfaDisableRequest(String code) {}

    public AuthController(
            AuthService auth,
            AuditLogService audit,
            Users users,
            UserSessions sessions,
            Optional<ClientRegistrationRepository> providers,
            SignInMethodPolicy methods,
            TotpService totp,
            com.asmolabs.vectispire.core.services.BrandingProperties branding,
            Clock clock) {
        this.providers = providers;
        this.methods = methods;
        this.auth = auth;
        this.audit = audit;
        this.users = users;
        this.sessions = sessions;
        this.totp = totp;
        this.branding = branding;
        this.clock = clock;
    }

    /** @param clientId the throttle's second counter. Never the IP alone — see {@link AuthService} */
    public record LoginRequest(String username, String password, @JsonProperty("client_id") String clientId) {}

    public record LoginResponse(
            String token,
            Instant expiresAt,
            UserSummary user,
            @JsonProperty("mfa_required") boolean mfaRequired,
            @JsonProperty("mfa_token") String mfaToken) {}

    public record UserSummary(String username, String displayName, String role, boolean mustChangePassword, boolean mfaEnabled) {}

    public record ChangePasswordRequest(@JsonProperty("current_password") String currentPassword, @JsonProperty("new_password") String newPassword) {}

    @Operation(summary = "User login", description = "Authenticates user by credentials and issues a JWT session bearer token or an MFA challenge.")
    @ApiResponse(responseCode = "200", description = "Authentication successful or MFA challenge initiated")
    @OpenToAnonymous
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest body, HttpServletRequest request) {
        if (!methods.passwordAllowed()) {
            audit.record(new AuditLogService.Record(
                    AuditOperation.LOGIN_BLOCKED,
                    text(body == null ? null : body.username()),
                    "Password sign-in is disabled on this deployment",
                    text(body == null ? null : body.username()),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Password sign-in is disabled here. Use single sign-on.");
        }

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
            case AuthService.Outcome.Blocked blocked -> throw throttled(blocked.retryAfter());
            case AuthService.Outcome.Invalid ignored ->
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials.");
            case AuthService.Outcome.Success success -> {
                if (success.user().getMfaEnabled()) {
                    String mfaToken = java.util.UUID.randomUUID().toString();
                    rememberChallenge(
                            mfaToken,
                            new MfaChallenge(
                                    success.user().getId(),
                                    clock.instant().plusSeconds(300),
                                    request.getHeader("User-Agent"),
                                    request.getRemoteAddr()));
                    yield new LoginResponse(null, null, null, true, mfaToken);
                }
                yield new LoginResponse(
                        success.issued().token(),
                        success.issued().session().getExpiresAt(),
                        summaryOf(success.user()),
                        false,
                        null);
            }
        };
    }

    @Operation(summary = "Verify MFA challenge", description = "Verifies TOTP authentication code and completes sign-in.")
    @ApiResponse(responseCode = "200", description = "MFA verified, JWT session issued")
    @OpenToAnonymous
    @PostMapping("/mfa/verify")
    public LoginResponse verifyMfa(@RequestBody MfaVerifyRequest body, HttpServletRequest request) {
        if (body == null || body.mfaToken() == null || body.code() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "MFA token and verification code are required.");
        }

        MfaChallenge challenge = mfaChallenges.get(body.mfaToken());
        if (challenge == null || clock.instant().isAfter(challenge.expiresAt())) {
            mfaChallenges.remove(body.mfaToken());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "MFA challenge has expired or is invalid. Please sign in again.");
        }

        UserEntity user = users.findById(challenge.userId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account not found."));

        if (!totp.verify(user, body.code())) {
            // **The challenge dies on the last try, and that is the control.** Leaving it alive
            // after a wrong code is what turns a six-digit secret into a five-minute exhaustive
            // search: the attacker keeps the same token and keeps going. Counting on the
            // challenge rather than the account also means a wrong guess cannot be used to lock
            // a legitimate user out — the worst it costs them is re-entering their password.
            boolean exhausted = challenge.attempts().incrementAndGet() >= MAX_MFA_ATTEMPTS;
            if (exhausted) {
                mfaChallenges.remove(body.mfaToken());
            }

            audit.record(new AuditLogService.Record(
                    AuditOperation.LOGIN_FAILURE,
                    user.getUsername(),
                    exhausted
                            ? "MFA challenge destroyed after " + MAX_MFA_ATTEMPTS
                                    + " invalid verification codes"
                            : "Invalid MFA verification code attempt",
                    user.getUsername(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));

            // The same message either way: which of the two it is tells an attacker how many
            // tries are left, and tells a legitimate user nothing they cannot see by trying.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid verification code.");
        }

        mfaChallenges.remove(body.mfaToken());
        AuthService.IssuedSession session = auth.openSessionForUser(user, challenge.userAgent(), challenge.ipAddress());

        audit.record(new AuditLogService.Record(
                AuditOperation.LOGIN_SUCCESS,
                user.getUsername(),
                "Signed in with MFA / TOTP: " + user.getUsername(),
                user.getUsername(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return new LoginResponse(
                session.token(),
                session.session().getExpiresAt(),
                summaryOf(user),
                false,
                null);
    }

    /**
     * Stores a challenge, sweeping the ones nobody came back for.
     *
     * <p>An abandoned sign-in — the user closes the tab between the password and the code —
     * leaves an entry that only a later presentation of the same token would remove, and there
     * will not be one. Sweeping on write rather than on a timer keeps the cost proportional to
     * the traffic that creates the entries.
     *
     * <p>The cap after the sweep is the backstop for the case the sweep cannot help with: ten
     * thousand <em>live</em> challenges means something is generating them faster than they
     * expire, and refusing is better than growing. It answers 503 rather than 500 because the
     * condition is transient by construction — five minutes clears it.
     *
     * <p><b>In memory, hence per-instance.</b> Two control planes behind a load balancer do not
     * share this map: the code has to come back to the instance that issued the token, so a
     * multi-instance deployment needs session affinity on {@code /api/v1/auth/**} until this
     * moves to the database. Written down here because nothing else says it.
     */
    private void rememberChallenge(String token, MfaChallenge challenge) {
        Instant now = clock.instant();
        mfaChallenges.values().removeIf(held -> now.isAfter(held.expiresAt()));

        if (mfaChallenges.size() >= MAX_MFA_CHALLENGES) {
            throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Too many sign-ins are awaiting verification. Try again in a few minutes.");
        }

        mfaChallenges.put(token, challenge);
    }

    @Operation(summary = "Setup MFA / TOTP", description = "Generates a new TOTP secret and QR code URI for 2FA setup.")
    @ApiResponse(responseCode = "200", description = "MFA setup payload")
    @RequiresAccount
    @PostMapping("/mfa/setup")
    public TotpService.SetupResponse setupMfa(@AuthenticationPrincipal VectispirePrincipal principal) {
        return totp.setup(principal.requireUser());
    }

    @Operation(summary = "Enable MFA", description = "Confirms TOTP setup by verifying the first code.")
    @ApiResponse(responseCode = "200", description = "MFA activated")
    @RequiresAccount
    @PostMapping("/mfa/enable")
    public TotpService.EnableResponse enableMfa(
            @RequestBody MfaEnableRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal) {
        if (body == null || body.secret() == null || body.code() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Secret and verification code are required.");
        }
        return totp.enable(principal.requireUser(), body.secret(), body.code());
    }

    @Operation(summary = "Disable MFA", description = "Deactivates 2FA after providing verification code.")
    @ApiResponse(responseCode = "200", description = "MFA disabled")
    @RequiresAccount
    @PostMapping("/mfa/disable")
    public Map<String, Boolean> disableMfa(
            @RequestBody MfaDisableRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal) {
        if (body == null || body.code() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification code is required to disable MFA.");
        }
        totp.disable(principal.requireUser(), body.code());
        return Map.of("mfaEnabled", false);
    }

    /**
     * @param configured whether an identity provider is wired at all — the screen offers the
     *     button only then, because an optional feature that is off should be absent rather than
     *     present and refusing
     * @param password whether a password may still be exchanged for a session. False makes the
     *     screen hide the form rather than offer one that answers 403 — an input that cannot
     *     work is worse than no input
     */
    public record SignInMethods(
            boolean configured,
            String label,
            boolean password,
            String brandName,
            String gitlabUrl) {}

    /**
     * What this deployment accepts as a way in.
     */
    @Operation(summary = "Get available sign-in methods", description = "Discovers whether password login and/or SSO OIDC providers are enabled.")
    @ApiResponse(responseCode = "200", description = "Sign-in methods availability")
    @OpenToAnonymous
    @GetMapping("/methods")
    public SignInMethods methods() {
        return new SignInMethods(
                providers.isPresent(),
                providers.map(this::labelOf).orElse(null),
                methods.passwordAllowed(),
                branding.name(),
                branding.gitlabUrl());
    }

    /**
     * Exchanges the one-time hand-off cookie for the session token.
     */
    @Operation(summary = "Exchange SSO hand-off cookie for session", description = "Trades temporary SSO callback cookie for a full JWT session.")
    @ApiResponse(responseCode = "200", description = "Session established successfully")
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

        return new LoginResponse(token, session.getExpiresAt(), summaryOf(user), false, null);
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
    public void logout(@AuthenticationPrincipal VectispirePrincipal principal) {
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
            @AuthenticationPrincipal VectispirePrincipal principal,
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
    public ResponseEntity<UserSummary> me(@AuthenticationPrincipal VectispirePrincipal principal) {
        return ResponseEntity.ok(summaryOf(principal.requireUser()));
    }

    private static UserSummary summaryOf(UserEntity user) {
        return new UserSummary(
                user.getUsername(), user.getDisplayName(), user.getRole(), user.getMustChangePassword(), user.getMfaEnabled());
    }

    private static String clientId(LoginRequest body, HttpServletRequest request) {
        String supplied = text(body == null ? null : body.clientId());
        return supplied.isEmpty() ? String.valueOf(request.getRemoteAddr()) : supplied;
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    /**
     * The account throttle's refusal, answered the way the address limiter answers.
     *
     * <p><b>Two limiters guard this endpoint and they used to disagree about the contract.</b>
     * {@code LoginRateLimitFilter} keys on the caller's address and returns {@code Retry-After};
     * this one keys on the *account* and returned a bare 429 whose wait was legible only inside an
     * English sentence. So a client that honours {@code Retry-After} — every HTTP library, and
     * this application's own sign-in screen, which reads {@code retryAfterSeconds} — was told
     * nothing by whichever of the two happened to fire first. Which one fires first depends on
     * whether the attempts share an address or a username, so the behaviour was not even stable.
     *
     * <p>Found by running the browser suites: the burst case asserts the header, got a 429 from
     * this path rather than from the filter, and failed on a header nobody had noticed was
     * missing.
     */
    private static ResponseStatusException throttled(java.time.Duration retryAfter) {
        long seconds = Math.max(1, retryAfter.toSeconds());
        return new ResponseStatusException(
                HttpStatus.TOO_MANY_REQUESTS, "Too many attempts. Try again in " + seconds + "s.") {
            @Override
            public org.springframework.http.HttpHeaders getHeaders() {
                org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
                headers.set("Retry-After", String.valueOf(seconds));
                headers.set("X-Rate-Limit-Retry-After-Seconds", String.valueOf(seconds));
                return headers;
            }
        };
    }

}

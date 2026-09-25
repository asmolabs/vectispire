package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.core.api.security.TrustedProxies;
import com.asmolabs.vectispire.core.api.security.OpenToAnonymous;
import com.asmolabs.vectispire.core.api.security.PasswordChangeGate;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.OidcConfiguration;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.AuthService;
import com.asmolabs.vectispire.core.services.AuthenticationFlowService;
import com.asmolabs.vectispire.core.services.AuthenticationFlowService.Handoff;
import com.asmolabs.vectispire.core.services.AuthenticationFlowService.SignIn;
import com.asmolabs.vectispire.core.services.AuthenticationFlowService.Verification;
import com.asmolabs.vectispire.core.services.TotpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
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
@Tag(name = "Authentication", description = "User login, MFA, SSO and session management")
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthenticationFlowService flows;
    private final AuthService auth;
    private final TotpService totp;
    private final com.asmolabs.vectispire.core.services.BrandingProperties branding;
    private final TrustedProxies proxies;

    public record MfaVerifyRequest(@JsonProperty("mfa_token") String mfaToken, String code) {}
    public record MfaEnableRequest(String secret, String code) {}
    public record MfaDisableRequest(String code) {}

    public AuthController(
            AuthenticationFlowService flows,
            AuthService auth,
            TotpService totp,
            com.asmolabs.vectispire.core.services.BrandingProperties branding,
            TrustedProxies proxies) {
        this.flows = flows;
        this.auth = auth;
        this.totp = totp;
        this.branding = branding;
        this.proxies = proxies;
    }

    /**
     * No {@code client_id}: the throttle's second counter is the caller's address, resolved here,
     * because a key the caller supplies is one it can change — see {@link AuthService.LoginRequest}.
     */
    public record LoginRequest(String username, String password) {}

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
        SignIn outcome = flows.signIn(new AuthenticationFlowService.Attempt(
                text(body == null ? null : body.username()),
                text(body == null ? null : body.password()),
                request.getHeader("User-Agent"),
                proxies.clientAddress(request)));

        return switch (outcome) {
            case SignIn.PasswordDisabled ignored -> throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "Password sign-in is disabled here. Use single sign-on.");
            case SignIn.Throttled throttled -> throw throttled(throttled.retryAfter());
            case SignIn.Refused ignored ->
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials.");
            // 503 rather than 500: the condition is transient by construction, and five minutes
            // clears it.
            case SignIn.ChallengesSaturated ignored -> throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Too many sign-ins are awaiting verification. Try again in a few minutes.");
            case SignIn.ChallengeIssued challenge -> new LoginResponse(null, null, null, true, challenge.mfaToken());
            case SignIn.SignedIn signedIn -> new LoginResponse(
                    signedIn.issued().token(),
                    signedIn.issued().session().getExpiresAt(),
                    summaryOf(signedIn.user()),
                    false,
                    null);
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

        return switch (flows.verify(
                body.mfaToken(), body.code(), request.getHeader("User-Agent"), proxies.clientAddress(request))) {
            case Verification.ChallengeInvalid ignored -> throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "MFA challenge has expired or is invalid. Please sign in again.");
            case Verification.AccountMissing ignored ->
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account not found.");
            // The same message whether or not that code destroyed the challenge: which of the two
            // it is tells an attacker how many tries are left, and tells a legitimate user nothing
            // they cannot see by trying.
            case Verification.WrongCode ignored ->
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid verification code.");
            case Verification.Throttled throttled -> throw throttled(throttled.retryAfter());
            case Verification.Verified verified -> new LoginResponse(
                    verified.issued().token(),
                    verified.issued().session().getExpiresAt(),
                    summaryOf(verified.user()),
                    false,
                    null);
        };
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
        try {
            totp.disable(principal.requireUser(), body.code());
        } catch (TotpService.SecondFactorLockedException locked) {
            throw throttled(locked.retryAfter());
        }
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
        AuthenticationFlowService.SignInOptions options = flows.options();
        return new SignInMethods(
                options.singleSignOn(),
                options.label(),
                options.password(),
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

        return switch (flows.exchange(token)) {
            case Handoff.Expired ignored ->
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "This sign-on has expired.");
            case Handoff.AccountMissing ignored ->
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account not found.");
            case Handoff.Exchanged exchanged ->
                new LoginResponse(token, exchanged.session().getExpiresAt(), summaryOf(exchanged.user()), false, null);
        };
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

    @RequiresAccount
    @PasswordChangeGate
    @DeleteMapping("/session")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal VectispirePrincipal principal) {
        // The row disappears: signing out is real, including for a tab left open elsewhere.
        principal.session().ifPresent(auth::revoke);
    }

    /**
     * Changes one's own password; the rules, and why the other sessions close, are on
     * {@link AuthenticationFlowService#changePassword}.
     */
    @RequiresAccount
    @PasswordChangeGate
    @PostMapping("/change-password")
    public Map<String, Object> changePassword(
            @RequestBody ChangePasswordRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        AuthenticationFlowService.PasswordChange outcome = flows.changePassword(
                principal.requireUser(),
                principal.session(),
                text(body == null ? null : body.currentPassword()),
                text(body == null ? null : body.newPassword()),
                request.getRemoteAddr(),
                request.getHeader("User-Agent"));

        if (outcome == AuthenticationFlowService.PasswordChange.CURRENT_PASSWORD_WRONG) {
            // 401 and not 400: what is missing is proof of identity, not a well-formed field,
            // and the screen has to be able to tell the two apart.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Current password is incorrect.");
        }
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

package com.asmolabs.vectispire.core.access;

import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Single sign-on, {@code vectispire.oidc.*} — the provider, and what a federated sign-in may do.
 *
 * <p><b>One record, because the same key had two readers and two defaults.</b> Whether a privileged
 * account is linked on a claim was read by the sign-on and by SCIM provisioning, each with its own
 * {@code @Value} default; a change to one would have linked an administrator through one door and
 * refused it at the other. What each setting decides is told in {@code application.yaml} and on its
 * reader.
 *
 * @param issuer the realm's issuer URL. Absent, single sign-on is off: no registration, no chain, no
 *     button ({@code OidcConfiguration})
 * @param clientId required with an issuer
 * @param clientSecret empty for a public client
 * @param name the button's label
 * @param passwordLogin whether password sign-in stays on beside single sign-on ({@code SignInMethodPolicy})
 * @param linkPrivilegedAccounts whether a privileged account may be linked on its first sign-on by a claim
 * @param linkByClaim whether any account is linked on its first sign-on by a claim at all
 * @param requireMfa whether a sign-on whose token states no second factor is refused
 * @param mfaAmr the {@code amr} values that state one, comma-separated
 * @param mfaAcr the {@code acr} levels that state one, comma-separated; none by default
 */
@Validated
@ConfigurationProperties("vectispire.oidc")
public record OidcProperties(
        Optional<String> issuer,
        Optional<String> clientId,
        String clientSecret,
        @DefaultValue("Single sign-on") String name,
        @DefaultValue("true") boolean passwordLogin,
        boolean linkPrivilegedAccounts,
        @DefaultValue("true") boolean linkByClaim,
        boolean requireMfa,
        @DefaultValue("mfa,otp,hwk,fido") String mfaAmr,
        String mfaAcr) {

    public OidcProperties {
        issuer = issuer == null ? Optional.empty() : issuer;
        clientId = clientId == null ? Optional.empty() : clientId;
        clientSecret = clientSecret == null ? "" : clientSecret;
        mfaAcr = mfaAcr == null ? "" : mfaAcr;
    }
}

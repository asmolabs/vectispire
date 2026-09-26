package com.asmolabs.vectispire.core.services.access;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * What the identity provider says about the second factor of a single sign-on, and whether that is
 * enough.
 *
 * <p><b>A federated session skips Vectispire's own TOTP, by design.</b> Delegating authentication
 * delegates the second factor with it: asking for a local code on top would make two factors
 * compete, and people would switch one off. But "the provider handles MFA" was an assumption nobody
 * could check. The provider now says what it did — the {@code amr} values of RFC 8176, or an
 * {@code acr} level the operator names — that statement is written into the audit entry of every
 * federated sign-in, and a deployment that requires it refuses a sign-on that does not carry it.
 */
@Service
public class FederatedSecondFactorPolicy {

    private final boolean required;
    private final Set<String> acceptedAmr;
    private final Set<String> acceptedAcr;

    public FederatedSecondFactorPolicy(
            @Value("${vectispire.oidc.require-mfa:false}") boolean required,
            @Value("${vectispire.oidc.mfa-amr:mfa,otp,hwk,fido}") String acceptedAmr,
            @Value("${vectispire.oidc.mfa-acr:}") String acceptedAcr) {
        this.required = required;
        this.acceptedAmr = values(acceptedAmr);
        this.acceptedAcr = values(acceptedAcr);
    }

    /**
     * The evidence the token carries, for the audit entry: {@code amr=otp,pwd}, {@code acr=gold}, or
     * empty when it states no second factor.
     */
    public Optional<String> evidence(List<String> amr, String acr) {
        List<String> methods = amr == null ? List.of() : amr;
        boolean byMethod = methods.stream().map(FederatedSecondFactorPolicy::normalized).anyMatch(acceptedAmr::contains);
        boolean byLevel = acr != null && acceptedAcr.contains(normalized(acr));
        if (!byMethod && !byLevel) {
            return Optional.empty();
        }
        return Optional.of(byMethod ? "amr=" + String.join(",", methods) : "acr=" + acr);
    }

    /**
     * Refuses when the deployment requires a second factor and the token states none.
     *
     * @return the evidence, or a sentence saying none was stated — the audit entry records either
     */
    public String require(List<String> amr, String acr) {
        Optional<String> evidence = evidence(amr, acr);
        if (evidence.isEmpty() && required) {
            throw new ExternalIdentityService.SignInRefusedException(
                    ExternalIdentityService.Refusal.MFA_REQUIRED,
                    "The identity provider stated no second factor for this sign-on, and this deployment requires one.");
        }
        return evidence.map(found -> "second factor stated by the provider (" + found + ")")
                .orElse("no second factor stated by the provider");
    }

    private static Set<String> values(String configured) {
        return Arrays.stream(configured == null ? new String[0] : configured.split(","))
                .map(FederatedSecondFactorPolicy::normalized)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}

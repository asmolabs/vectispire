package com.asmolabs.vectispire.core.access.web.security;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.web.security.chain.CredentialConfinement;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This route also accepts an integration API key holding {@code value} (decision 0024).
 *
 * <p>Opt-in, never the default: a key reaches only the routes that carry this marker, whatever its
 * account's role would allow — see {@link CredentialConfinement}. The role markers still apply on
 * top, so a key never does more than its account could. Nothing administrative carries it.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface AcceptsApiKey {

    ApiKeyScope value();
}

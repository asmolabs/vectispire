/**
 * What every module's controllers need from {@code access}: the route markers ({@code @Requires…},
 * {@code @AcceptsApiKey}, {@code @OpenToAnonymous}, {@code @PasswordChangeGate}), the principal, the
 * client address as the trusted proxies resolve it, the refusal helper ({@link
 * com.asmolabs.vectispire.core.access.web.security.Visibilities}), the audit actor built from a request,
 * and the exceptions the chain raises for the error handler to map.
 *
 * <p><b>A named interface</b> (decision 0028) — one of three, with the {@code queries} of {@code
 * scanning} and {@code issues} (decision 0029) — that a module lists as {@code access::security} among
 * its allowed dependencies. Everything else {@code access} publishes is at its root; this is not,
 * because it is web vocabulary — route annotations, a Spring Security token, a helper taking an {@code
 * HttpServletRequest} — and a module's root is its service layer.
 * Put there, the principal would become something a service could take as a parameter, and the
 * actor of an audit entry something a service could read off a request: both have been spoofable
 * here before, and keeping them in {@code web} keeps services deciding on what they are handed. The
 * filter chain that enforces these markers is in {@code .chain}, beneath: it is {@code access}'s own
 * business, and no other module has a reason to name a filter.
 *
 * <p>It was {@code core.api.security}, beside every controller. It belongs to {@code access} because
 * everything in it answers "who is calling, and what may they see" — the principal holds {@code
 * access}'s views, the filters call its services — and a separate security module would have depended
 * on {@code access} while {@code access}'s own controllers depended on it: a cycle.
 */
@NamedInterface("security")
package com.asmolabs.vectispire.core.access.web.security;

import org.springframework.modulith.NamedInterface;

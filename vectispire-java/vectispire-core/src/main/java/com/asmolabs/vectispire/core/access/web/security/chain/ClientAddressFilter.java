package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.core.access.web.security.TrustedProxies;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the client's address once, at the head of the chain, for everything that records it.
 *
 * <p><b>The audit trail named the load balancer.</b> The throttles resolved the client through
 * {@link TrustedProxies}, and the rest read {@code getRemoteAddr()}: behind a proxy, every audit
 * entry written through {@code RequestActors}, every refusal the access-denied handler recorded and
 * every triage, import and review a route attributed carried the proxy's address — the one fact
 * about the caller an investigation starts from. Those callers are static helpers and handlers with
 * no {@code TrustedProxies} of their own, so the address is resolved here and read back with
 * {@link TrustedProxies#resolvedClientAddress}; {@code ArchitectureTest} refuses
 * {@code getRemoteAddr()} anywhere else.
 *
 * <p>In the chain rather than only as a servlet filter, so the HTTP suite — which assembles the
 * chain — exercises it.
 */
@Component
public class ClientAddressFilter extends OncePerRequestFilter {

    private final TrustedProxies proxies;

    public ClientAddressFilter(TrustedProxies proxies) {
        this.proxies = proxies;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        request.setAttribute(TrustedProxies.CLIENT_ADDRESS, proxies.clientAddress(request));
        chain.doFilter(request, response);
    }
}

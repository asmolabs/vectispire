package com.asmolabs.vectispire.common.domain.apis;

import java.util.List;

/**
 * High level summary of attack surface and API posture.
 */
public record AttackSurfaceSummary(
        int totalEndpoints,
        int publicEndpoints,
        int internalEndpoints,
        int unauthenticatedEndpoints,
        int shadowEndpoints,
        int sensitiveUnprotectedEndpoints) {

    public static AttackSurfaceSummary from(List<ApiEndpoint> endpoints, ShadowApiDiff diff) {
        if (endpoints == null) endpoints = List.of();
        int total = endpoints.size();
        int pub = 0;
        int intern = 0;
        int unauth = 0;
        int sensitiveUnprot = 0;

        for (ApiEndpoint ep : endpoints) {
            if (ep.visibility() == ApiVisibility.PUBLIC) pub++;
            else if (ep.visibility() == ApiVisibility.INTERNAL) intern++;

            if (!ep.authRequired()) {
                unauth++;
                if (ep.isSensitivePath()) {
                    sensitiveUnprot++;
                }
            }
        }

        int shadow = diff != null ? diff.shadowEndpoints().size() : 0;

        return new AttackSurfaceSummary(total, pub, intern, unauth, shadow, sensitiveUnprot);
    }
}

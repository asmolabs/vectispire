package com.asmolabs.vectispire.common.domain.apis;

public enum ShadowApiStatus {
    /** Present in code and declared in OpenAPI contract. */
    DOCUMENTED,
    /** Present in code but absent from all declared OpenAPI contracts. */
    SHADOW_API,
    /** Declared in OpenAPI contract but not found implemented in code. */
    ZOMBIE_API
}

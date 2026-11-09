package com.asmolabs.vectispire.common.domain.attackpath;

/**
 * The classification of a node in an attack execution path.
 */
public enum AttackPathNodeType {
    INTERNET_INGRESS,
    API_ENDPOINT,
    VULNERABLE_COMPONENT,
    SECRET,
    DATABASE,
    INFRASTRUCTURE
}

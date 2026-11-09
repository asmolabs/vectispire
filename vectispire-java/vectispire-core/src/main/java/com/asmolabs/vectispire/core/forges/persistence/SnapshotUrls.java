package com.asmolabs.vectispire.core.forges.persistence;

import java.util.UUID;

/** A repository of a connection's snapshot by its clone URLs: what the change-review reading matches a target to. */
public record SnapshotUrls(UUID connectionId, String forgeId, String httpUrl, String sshUrl) {}

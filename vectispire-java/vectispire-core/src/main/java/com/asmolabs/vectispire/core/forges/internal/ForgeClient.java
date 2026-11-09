package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeAddress;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal;
import com.asmolabs.vectispire.common.domain.forges.ForgeCredential;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import java.time.Instant;
import java.util.Optional;

/**
 * One forge's REST API, behind the interface the discovery is written against (decision 0037 §1): one
 * adapter per forge, the job, the snapshot and the import written once. Lot D1 has the probe; the listing
 * of namespaces and repositories is D3's (GitLab) and D4's (GitHub).
 *
 * <p>Every call goes through {@code OutboundJson} — the guard, the pin, no redirect — and never through a
 * client of the adapter's own.
 */
public interface ForgeClient {

    ForgeKind kind();

    /**
     * Presents the token to the forge once and reads what the forge says about it.
     *
     * @throws ForgeConnectionRefusal for every reason a connection is not made, with the sentence to show
     */
    Probe probe(Target target, String token);

    /**
     * Where and how to reach the forge.
     *
     * @param owner GitHub's organisation or user; null for GitLab
     * @param trust the CA pinned for this server; empty for the runtime's trust store
     */
    record Target(ForgeAddress address, String owner, OutboundPolicy policy, Optional<PinnedCa> trust) {}

    /**
     * What the forge said.
     *
     * @param expiresAt empty when the forge reported no expiry
     * @param version empty for the clouds, which state none, and when it could not be read
     */
    record Probe(ForgeCredential credential, Optional<Instant> expiresAt, Optional<String> version) {}
}

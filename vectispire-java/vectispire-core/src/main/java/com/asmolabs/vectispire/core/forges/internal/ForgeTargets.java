package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeAddress;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import java.time.Instant;
import java.util.Optional;

/**
 * Where and how a stored connection's requests go — one reading for the probe and for the discovery, so that the
 * address, the policy and the pinned CA a discovery uses are the ones the connection was probed with.
 */
public final class ForgeTargets {

    /** How the pinned CA's refusals name the field. */
    public static final PinnedCa.Subject CA = new PinnedCa.Subject("The forge's CA", "the forge");

    private ForgeTargets() {}

    /**
     * The target of a stored connection, the address derived again from the stored web address rather than
     * stored apart from it: the derivation is the rule.
     */
    public static ForgeClient.Target of(ForgeConnectionEntity entity, boolean internal, Optional<PinnedCa> ca) {
        ForgeAddress address = ForgeAddress.of(ForgeKind.parse(entity.getKind()), entity.getBaseUrl());
        return new ForgeClient.Target(address, entity.getOwner(), policyOf(internal), ca);
    }

    /**
     * The stored CA, checked current at every use as the SIEM checks its collector's: the JDK does not read a
     * trust anchor's dates, and a lapsed CA must not vouch for the server.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException when it is no longer valid
     */
    public static Optional<PinnedCa> storedCa(ForgeConnectionEntity entity, Instant now) {
        return Optional.ofNullable(entity.getCaPem()).map(pem -> PinnedCa.parse(pem, now, CA));
    }

    /** {@code INTERNAL_ALLOWED} on the administrator's statement, {@code PUBLIC_ONLY} otherwise. */
    public static OutboundPolicy policyOf(boolean internal) {
        return internal ? OutboundPolicy.INTERNAL_ALLOWED : OutboundPolicy.PUBLIC_ONLY;
    }
}

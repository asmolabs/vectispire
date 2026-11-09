package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import java.util.Collection;
import java.util.Optional;

/**
 * Which triage decisions a SOC hears about.
 *
 * <p>Not every triage: marking an issue "under review" is housekeeping, and a queue of requests
 * awaiting approval is the control working. What is forwarded is what takes a finding out of the
 * gate's way, and the answer to a four-eyes request:
 *
 * <ul>
 *   <li>a settling status — {@code not_affected}, {@code fixed} — reached directly:
 *       {@link SecurityEventType#TRIAGE_SETTLED};
 *   <li>the same reached from {@code pending_approval}: {@link SecurityEventType#TRIAGE_APPROVED};
 *   <li>{@code pending_approval} sent back to a status that settles nothing:
 *       {@link SecurityEventType#TRIAGE_REFUSED}.
 * </ul>
 *
 * <p>Settling is asked of {@link TriageStatus#isSettled()} rather than listed, for the reason the
 * four-eyes rule gives: a settling status added later is forwarded the day it is marked settling.
 */
public final class TriageSignals {

    private TriageSignals() {}

    /**
     * @param previous the statuses the issues had before the decision, by wire name — one for a
     *     single triage, several for a bulk one, where a single request among them makes the decision
     *     an answer to a request
     * @param result the status the decision left, by wire name — which, for an author who cannot
     *     approve, is {@code pending_approval} whatever was asked, and signals nothing
     */
    public static Optional<SecurityEventType> of(Collection<String> previous, String result) {
        Optional<TriageStatus> after = TriageStatus.fromWireName(result);
        if (after.isEmpty()) {
            return Optional.empty();
        }
        boolean answersARequest = previous.stream()
                .map(TriageStatus::fromWireName)
                .anyMatch(status -> status.filter(TriageStatus.PENDING_APPROVAL::equals).isPresent());
        if (after.get().isSettled()) {
            return Optional.of(answersARequest ? SecurityEventType.TRIAGE_APPROVED : SecurityEventType.TRIAGE_SETTLED);
        }
        if (answersARequest && after.get() != TriageStatus.PENDING_APPROVAL) {
            return Optional.of(SecurityEventType.TRIAGE_REFUSED);
        }
        return Optional.empty();
    }
}

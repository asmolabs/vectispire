package com.asmolabs.vectispire.common.domain.threatintel;

import java.time.Instant;

/**
 * Where the CISA KEV catalogue stands: when it was last read, how old what was read is, and whether
 * the last attempt worked.
 *
 * @param lastSyncedAt when the catalogue was last read and applied — null until the first time. A
 *     failed attempt leaves it where it was: the catalogue in use is still that one
 * @param totalCves the identifiers the feed table holds, the catalogue's and those it has dropped
 * @param totalKev the identifiers the last catalogue applied lists
 * @param status {@link State#NEVER_SYNCED}, {@link State#SYNCED}, or {@link State#FAILED} when the
 *     last attempt did not replace the catalogue — {@code lastError} says why
 * @param backlogUpdatedCount issues whose exploitation this synchronisation changed; zero on a read
 * @param kevCatalogVersion CISA's {@code catalogVersion} of the catalogue in use
 * @param kevReleasedAt CISA's {@code dateReleased} of the catalogue in use: the age of the data,
 *     which a mirror refreshed rarely makes different from {@code lastSyncedAt}
 * @param lastAttemptAt when a synchronisation was last tried, successful or not
 * @param lastError why the last attempt failed; null after a success
 */
public record ThreatIntelSyncStatus(
        Instant lastSyncedAt,
        long totalCves,
        long totalKev,
        State status,
        long backlogUpdatedCount,
        String kevCatalogVersion,
        Instant kevReleasedAt,
        Instant lastAttemptAt,
        String lastError) {

    /**
     * The three states of the feed, under the names the wire has always carried.
     *
     * <p>Not two: "never synced" and "the last attempt failed" both mean the backlog's exploitation
     * flags are not today's, but only the second has a catalogue in use, and a reason to show.
     */
    public enum State {
        NEVER_SYNCED,
        SYNCED,
        FAILED;

        /** A stored value this version does not know reads as failed: nothing says it worked. */
        public static State of(String stored) {
            if (stored == null) {
                return NEVER_SYNCED;
            }
            for (State state : values()) {
                if (state.name().equals(stored)) {
                    return state;
                }
            }
            return FAILED;
        }
    }
}

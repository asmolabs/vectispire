package com.asmolabs.vectispire.common.domain.threatintel;

import java.time.Instant;

/**
 * Where the two synchronised feeds stand — the CISA KEV catalogue in the top-level fields, FIRST's
 * EPSS file in {@link #epss()}: when each was last read, how old what was read is, and whether the
 * last attempt worked.
 *
 * <p>The KEV fields stay at the top level under the names the wire has carried since the catalogue
 * was first synchronised; EPSS is a record of its own rather than a second set of prefixed fields,
 * because its state is its own — fetched, refused and retried apart from the catalogue's.
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
 * @param epss where the EPSS file stands
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
        String lastError,
        EpssFeedStatus epss) {

    /**
     * Where FIRST's EPSS file stands.
     *
     * <p><b>Before the first synchronisation no score is known</b>, and every EPSS figure on screen is
     * absent rather than zero: zero is a measured probability, and reporting it for a CVE nobody
     * scored is the defect decision 0007 names.
     *
     * @param status {@link State#NEVER_SYNCED}, {@link State#SYNCED}, or {@link State#FAILED} when the
     *     last attempt did not replace the file in use — {@code lastError} says why
     * @param lastSyncedAt when a file was last read and applied, or confirmed unchanged
     * @param modelVersion the EPSS model that produced the scores in use, as the file declares it
     * @param scoreDate the day the scores in use are for, as the file declares it: the age of the data
     * @param totalScored the CVE the file in use scores
     * @param lastAttemptAt when a synchronisation was last tried, successful or not
     * @param lastError why the last attempt failed; null after a success
     * @param backlogUpdatedCount open issues whose score this synchronisation changed; zero on a read
     * @param inProgress whether a synchronisation holds the lease now — a lead's request made meanwhile
     *     is not run a second time
     */
    public record EpssFeedStatus(
            State status,
            Instant lastSyncedAt,
            String modelVersion,
            Instant scoreDate,
            long totalScored,
            Instant lastAttemptAt,
            String lastError,
            long backlogUpdatedCount,
            boolean inProgress) {

        /** Nothing read yet. */
        public static EpssFeedStatus never() {
            return new EpssFeedStatus(State.NEVER_SYNCED, null, null, null, 0, null, null, 0, false);
        }

        /** The same state, with the issues this synchronisation re-scored. */
        public EpssFeedStatus withBacklogUpdated(long count) {
            return new EpssFeedStatus(status, lastSyncedAt, modelVersion, scoreDate, totalScored, lastAttemptAt,
                    lastError, count, inProgress);
        }
    }

    /**
     * The three states of a feed, under the names the wire has always carried.
     *
     * <p>Not two: "never synced" and "the last attempt failed" both mean the backlog's figures are
     * not today's, but only the second has data in use, and a reason to show.
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

    /** The same KEV state, with the EPSS state replaced. */
    public ThreatIntelSyncStatus withEpss(EpssFeedStatus replaced) {
        return new ThreatIntelSyncStatus(lastSyncedAt, totalCves, totalKev, status, backlogUpdatedCount,
                kevCatalogVersion, kevReleasedAt, lastAttemptAt, lastError, replaced);
    }
}

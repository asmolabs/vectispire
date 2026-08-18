package com.asmolabs.zanshin.common.domain.exports;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import java.time.Instant;

/**
 * An issue as the exports read it.
 *
 * <p>Instants are canonicalized on the way out — never rendered by a driver's own
 * formatting, which drops sub-second precision and applies whatever timezone the process
 * happens to run in. Two exports of the same backlog from two machines must be the same
 * bytes.
 *
 * @param fingerprint what lets a platform match this issue across uploads even when the
 *     file moves and the line shifts
 * @param resolved whether the scanner has stopped seeing it
 * @param directDependency {@code null} when nothing is known — which is not the same as
 *     transitive, and the exports keep the difference
 */
public record ExportableIssue(
        long id,
        String fingerprint,
        FindingType type,
        String identifier,
        Severity severity,
        Double cvssScore,
        Double epssScore,
        boolean kev,
        String packageName,
        String packageVersion,
        String purl,
        Boolean directDependency,
        String filePath,
        Integer line,
        FixState fixState,
        String fixVersions,
        String link,
        String description,
        boolean resolved,
        TriageStatus triageStatus,
        String triageJustification,
        String triageComment,
        String triagedBy,
        Instant triagedAt,
        Instant triageExpiresAt,
        Instant firstSeenAt,
        Instant lastSeenAt,
        Integer timesSeen) {

    public ExportableIssue {
        severity = severity == null ? Severity.UNKNOWN : severity;
    }

    /** Whether a fix has been published upstream. */
    public enum FixState {
        FIXED("fixed"),
        NOT_FIXED("not-fixed"),
        WONT_FIX("wont-fix"),
        UNKNOWN("unknown");

        private final String wireName;

        FixState(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }
    }


    /**
     * A fluent builder, because twenty-eight positional arguments is not a call site anybody
     * can read or review.
     *
     * <p>Every field has a defensible default — absent — so a caller states only what it knows.
     * That matters most in tests, where the point of a case is the two fields it sets, and the
     * other twenty-six are noise that hides it.
     */
    public static final class Builder {
        private long id = 1;
        private String fingerprint;
        private FindingType type;
        private String identifier;
        private Severity severity = Severity.UNKNOWN;
        private Double cvssScore;
        private Double epssScore;
        private boolean kev;
        private String packageName;
        private String packageVersion;
        private String purl;
        private Boolean directDependency;
        private String filePath;
        private Integer line;
        private FixState fixState;
        private String fixVersions;
        private String link;
        private String description;
        private boolean resolved;
        private TriageStatus triageStatus;
        private String triageJustification;
        private String triageComment;
        private String triagedBy;
        private Instant triagedAt;
        private Instant triageExpiresAt;
        private Instant firstSeenAt;
        private Instant lastSeenAt;
        private Integer timesSeen;

        public Builder id(long value) { this.id = value; return this; }
        public Builder fingerprint(String value) { this.fingerprint = value; return this; }
        public Builder type(FindingType value) { this.type = value; return this; }
        public Builder identifier(String value) { this.identifier = value; return this; }
        public Builder severity(Severity value) { this.severity = value; return this; }
        public Builder cvssScore(Double value) { this.cvssScore = value; return this; }
        public Builder epssScore(Double value) { this.epssScore = value; return this; }
        public Builder kev(boolean value) { this.kev = value; return this; }
        public Builder packageName(String value) { this.packageName = value; return this; }
        public Builder packageVersion(String value) { this.packageVersion = value; return this; }
        public Builder purl(String value) { this.purl = value; return this; }
        public Builder directDependency(Boolean value) { this.directDependency = value; return this; }
        public Builder filePath(String value) { this.filePath = value; return this; }
        public Builder line(Integer value) { this.line = value; return this; }
        public Builder fixState(FixState value) { this.fixState = value; return this; }
        public Builder fixVersions(String value) { this.fixVersions = value; return this; }
        public Builder link(String value) { this.link = value; return this; }
        public Builder description(String value) { this.description = value; return this; }
        public Builder resolved(boolean value) { this.resolved = value; return this; }
        public Builder triageStatus(TriageStatus value) { this.triageStatus = value; return this; }
        public Builder triageJustification(String value) { this.triageJustification = value; return this; }
        public Builder triageComment(String value) { this.triageComment = value; return this; }
        public Builder triagedBy(String value) { this.triagedBy = value; return this; }
        public Builder triagedAt(Instant value) { this.triagedAt = value; return this; }
        public Builder triageExpiresAt(Instant value) { this.triageExpiresAt = value; return this; }
        public Builder firstSeenAt(Instant value) { this.firstSeenAt = value; return this; }
        public Builder lastSeenAt(Instant value) { this.lastSeenAt = value; return this; }
        public Builder timesSeen(Integer value) { this.timesSeen = value; return this; }

        public ExportableIssue build() {
            return new ExportableIssue(
                    id, fingerprint, type, identifier, severity, cvssScore, epssScore, kev, packageName,
                    packageVersion, purl, directDependency, filePath, line, fixState, fixVersions, link,
                    description, resolved, triageStatus, triageJustification, triageComment, triagedBy,
                    triagedAt, triageExpiresAt, firstSeenAt, lastSeenAt, timesSeen);
        }
    }

    boolean hasFixVersions() {
        return fixVersions != null && !fixVersions.isBlank();
    }
}

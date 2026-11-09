package com.asmolabs.vectispire.common.domain.scorecard;

/**
 * Letter grade representing target security posture and maturity — or {@link #NO_DATA}, which is not a
 * grade.
 */
public enum SecurityGrade {
    A_PLUS("A+", "#4c1", "Exemplary — Zero critical debt, full SLA compliance"),
    A("A", "#97ca00", "Strong — Excellent hygiene with minimal residual risk"),
    B("B", "#dfb317", "Moderate — Acceptable risk with standard maintenance items"),
    C("C", "#fe7d37", "Needs Attention — Pending high severity or overdue SLAs"),
    D("D", "#e05d44", "High Risk — Unresolved critical vulnerabilities or KEV threats"),
    F("F", "#d9534f", "Critical Failure — Major security debt and multiple SLA breaches"),
    /**
     * Nothing in scope was ever scanned to completion, so there is nothing to grade (decision 0007:
     * absent is not empty). The score starts at a hundred and subtracts what it finds, so a target
     * nobody examined used to read A+ — on its card, on its project's, and on the public badge of a
     * repository registered and never scanned. Never returned by {@link #fromScore}: it is decided
     * before any score exists, and the scorecard carrying it carries no score.
     */
    NO_DATA("no data", "#9f9f9f", "No data — Nothing in scope has been scanned to completion");

    private final String label;
    private final String badgeColor;
    private final String description;

    SecurityGrade(String label, String badgeColor, String description) {
        this.label = label;
        this.badgeColor = badgeColor;
        this.description = description;
    }

    public String getLabel() {
        return label;
    }

    public String getBadgeColor() {
        return badgeColor;
    }

    public String getDescription() {
        return description;
    }

    public static SecurityGrade fromScore(int score) {
        if (score >= 95) return A_PLUS;
        if (score >= 85) return A;
        if (score >= 70) return B;
        if (score >= 55) return C;
        if (score >= 40) return D;
        return F;
    }
}

package com.asmolabs.vectispire.common.domain.scorecard;

/**
 * Letter grade representing target security posture and maturity.
 */
public enum SecurityGrade {
    A_PLUS("A+", "#4c1", "Exemplary — Zero critical debt, full SLA compliance"),
    A("A", "#97ca00", "Strong — Excellent hygiene with minimal residual risk"),
    B("B", "#dfb317", "Moderate — Acceptable risk with standard maintenance items"),
    C("C", "#fe7d37", "Needs Attention — Pending high severity or overdue SLAs"),
    D("D", "#e05d44", "High Risk — Unresolved critical vulnerabilities or KEV threats"),
    F("F", "#d9534f", "Critical Failure — Major security debt and multiple SLA breaches");

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

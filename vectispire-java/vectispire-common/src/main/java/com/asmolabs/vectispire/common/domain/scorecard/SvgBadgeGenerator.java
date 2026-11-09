package com.asmolabs.vectispire.common.domain.scorecard;

/**
 * Pure Java generator for clean, vector SVG security badges (Shields.io style).
 */
public final class SvgBadgeGenerator {

    private SvgBadgeGenerator() {}

    public static String generateBadge(String subject, String status, String statusColor) {
        String label = subject != null ? subject : "security";
        String grade = status != null ? status : "A+";
        String color = statusColor != null ? statusColor : "#4c1";

        int labelWidth = 6 * label.length() + 20;
        int statusWidth = 7 * grade.length() + 18;
        int totalWidth = labelWidth + statusWidth;

        int labelTextX = (labelWidth * 10) / 2;
        int statusTextX = (labelWidth * 10) + (statusWidth * 10) / 2;

        return """
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <linearGradient id="s" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="%d" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>
    <text x="%d" y="140" transform="scale(.1)" fill="#fff" textLength="%d">%s</text>
    <text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>
    <text x="%d" y="140" transform="scale(.1)" fill="#fff" font-weight="bold" textLength="%d">%s</text>
  </g>
</svg>""".formatted(
                totalWidth, label, grade,
                label, grade,
                totalWidth,
                labelWidth,
                labelWidth, statusWidth, color,
                totalWidth,
                labelTextX, (labelWidth - 10) * 10, label,
                labelTextX, (labelWidth - 10) * 10, label,
                statusTextX, (statusWidth - 10) * 10, grade,
                statusTextX, (statusWidth - 10) * 10, grade);
    }
}

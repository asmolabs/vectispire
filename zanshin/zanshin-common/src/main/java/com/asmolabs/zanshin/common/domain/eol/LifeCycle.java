package com.asmolabs.zanshin.common.domain.eol;

import com.asmolabs.zanshin.common.domain.issues.Severity;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;

/**
 * Matching a version to its life cycle, and the verdict that follows.
 *
 * <p>Pure: everything that can genuinely go wrong here — a version prefix compared wrongly, a
 * date read askew, a purl carrying its architecture — is testable with no network. A service
 * only fetches the catalog and caches it.
 */
public final class LifeCycle {

    private LifeCycle() {}

    /** The default warning window. */
    public static final Duration DEFAULT_WARNING_WINDOW = Duration.ofDays(180);

    /**
     * A product release, as the catalog publishes it.
     *
     * @param eolFrom the day support ends, when the catalog knows it
     * @param maintained {@code false} with no date is the abandoned-product case
     */
    public record Release(String name, LocalDate eolFrom, Boolean eol, Boolean maintained, String latest) {}

    public record Product(String name, List<Release> releases) {

        public Product {
            releases = releases == null ? List.of() : List.copyOf(releases);
        }
    }

    /** The verdict on a cycle. Absent means comfortably supported. */
    public record Verdict(Severity severity, LocalDate eolDate) {}

    /**
     * The cycle a version belongs to.
     *
     * <p>The longest matching cycle wins, so a product publishing both "8" and "8.1" resolves
     * to the more specific one.
     */
    public static Optional<Release> matchRelease(Product product, String version) {
        Version wanted = Version.parse(version);

        Release best = null;
        int bestLength = -1;
        for (Release release : product.releases()) {
            Version cycle = Version.parse(release.name());
            if (cycle.isCycleOf(wanted) && cycle.length() > bestLength) {
                best = release;
                bestLength = cycle.length();
            }
        }
        return Optional.ofNullable(best);
    }

    /**
     * Assesses a cycle at a given date.
     *
     * <p><b>A cycle already past its end is {@link Severity#HIGH}</b> — not because something is
     * broken today, but because nothing will be fixed tomorrow, which is not a "medium" for a
     * component you ship. An end date still ahead is {@link Severity#MEDIUM}: a deadline, not an
     * incident.
     *
     * <p>Beyond the window, nothing is reported. Everything reaches end of life one day, and
     * flagging a version supported for another three years teaches people to filter this whole
     * finding type out — which costs more than the finding was worth.
     */
    public static Optional<Verdict> assess(Release release, LocalDate today, Duration warningWindow) {
        LocalDate eolDate = release.eolFrom();

        if (Boolean.TRUE.equals(release.eol()) || (eolDate != null && !eolDate.isAfter(today))) {
            return Optional.of(new Verdict(Severity.HIGH, eolDate));
        }

        if (eolDate != null) {
            long daysLeft = java.time.temporal.ChronoUnit.DAYS.between(today, eolDate);
            if (daysLeft >= 0 && daysLeft <= warningWindow.toDays()) {
                return Optional.of(new Verdict(Severity.MEDIUM, eolDate));
            }
        }

        // Not maintained, and no date to go with it: the abandoned-product case. There is no
        // deadline to warn about because the deadline has no date — which is worse, not milder.
        if (Boolean.FALSE.equals(release.maintained()) && eolDate == null) {
            return Optional.of(new Verdict(Severity.HIGH, null));
        }

        return Optional.empty();
    }

    /**
     * The most recent maintained release — that is, what "fix this" means here.
     *
     * <p>Carried on the finding's fix versions so an end-of-life finding reads like every other
     * actionable one, on screen as in the exports.
     */
    public static Optional<String> recommendedVersion(Product product) {
        for (Release release : product.releases()) {
            if (Boolean.TRUE.equals(release.maintained()) && !Boolean.TRUE.equals(release.eol())) {
                String name = release.latest() != null ? release.latest() : release.name();
                if (name != null && !name.isBlank()) {
                    return Optional.of(name);
                }
            }
        }
        return Optional.empty();
    }

    /** An ISO date from the catalog. Read as UTC so two machines agree on the day. */
    public static Optional<LocalDate> parseDate(String value) {
        if (value == null || value.length() < 10) {
            return Optional.empty();
        }
        try {
            return Optional.of(LocalDate.parse(value.substring(0, 10)));
        } catch (DateTimeParseException notADate) {
            return Optional.empty();
        }
    }

    /** Today, in UTC — the timezone the catalog's dates are expressed in. */
    public static LocalDate today(Instant now) {
        return now.atZone(ZoneOffset.UTC).toLocalDate();
    }
}

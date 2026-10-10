package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The targets a run's export carried, as the run records them, and who may read a document built over them
 * (decision 0042).
 *
 * <p><b>A document is evidence of a moment, and the project moves after it.</b> Served to whoever saw the
 * project whole at the time of the download, a document kept the findings of a repository taken out of the
 * project since, and handed them to a reader who sees the project as it is now and was never shown that
 * repository. The project's rule still applies; this is the second one, read off what the run recorded.
 */
public final class ReportRunTargets {

    private ReportRunTargets() {}

    /** The column's text: each target as an issue's fingerprint names it, space-separated, in the order given. */
    public static String record(Collection<ScanTarget> targets) {
        return targets.stream().map(ScanTarget::fingerprintKey).collect(Collectors.joining(" "));
    }

    /**
     * Whether this reader sees every target the export carried.
     *
     * <p><b>Not recorded is not empty</b> (decision 0007): a run from before the column says nothing of what its
     * export held, so only a reader who sees everything may read it — an empty set would have served it to
     * anybody seeing the project. Text that does not parse is read the same way rather than as fewer targets.
     *
     * @param recorded the run's {@code export_targets}, null on a run from before V87
     */
    public static boolean seenBy(String recorded, VisibilityService.Allowance allowance) {
        Visibility visibility = allowance.visibility();
        Optional<List<ScanTarget>> carried = parse(recorded);
        if (carried.isEmpty()) {
            return visibility instanceof Visibility.Everything && !allowance.narrowedByCredential();
        }
        return carried.get().stream().allMatch(visibility::permits);
    }

    static Optional<List<ScanTarget>> parse(String recorded) {
        if (recorded == null) {
            return Optional.empty();
        }
        List<ScanTarget> targets = new ArrayList<>();
        for (String key : recorded.strip().split(" +")) {
            if (key.isEmpty()) {
                continue;
            }
            Optional<ScanTarget> target = target(key);
            if (target.isEmpty()) {
                return Optional.empty();
            }
            targets.add(target.get());
        }
        return Optional.of(List.copyOf(targets));
    }

    private static Optional<ScanTarget> target(String key) {
        int colon = key.indexOf(':');
        if (colon < 0) {
            return Optional.empty();
        }
        long id;
        try {
            id = Long.parseLong(key.substring(colon + 1));
        } catch (NumberFormatException malformed) {
            return Optional.empty();
        }
        return switch (key.substring(0, colon)) {
            case "repo" -> Optional.of(new ScanTarget.Repository(id));
            case "container" -> Optional.of(new ScanTarget.Container(id));
            default -> Optional.empty();
        };
    }
}

package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifestStatus;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginManifestEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginManifestRepository;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Which documents are withdrawn: those whose run's manifest digest the governor withdrew (decision 0035 §4, lot R7).
 *
 * <p><b>Read off the manifest's row, never copied onto the documents.</b> A withdrawal writes one row; every run,
 * every download and every status answer reads it through the digest the run recorded at its claim. A flag stamped
 * on the documents by the withdrawal would miss the one a run still in hand produced after the stamp — the run
 * signs outside any transaction the withdrawal could see — and the document would then be served as standing by
 * an installation that had withdrawn its code. Read here, a document is withdrawn the instant its manifest is,
 * whenever it was produced.
 */
@Component
class ReportWithdrawals {

    private final ReportPluginManifestRepository manifests;

    ReportWithdrawals(ReportPluginManifestRepository manifests) {
        this.manifests = manifests;
    }

    /** The withdrawal of this manifest digest; empty for one that stands, or for a run with none. */
    Optional<ReportWithdrawal> of(String manifestDigest) {
        return Optional.ofNullable(manifestDigest).flatMap(manifests::findById).flatMap(ReportWithdrawals::withdrawal);
    }

    /**
     * The withdrawals of these digests, by digest — one statement for a listing, whose digests are as many as its
     * page: those that stand are absent from the map.
     */
    Map<String, ReportWithdrawal> of(Collection<String> manifestDigests) {
        var digests = manifestDigests.stream().filter(Objects::nonNull).distinct().toList();
        if (digests.isEmpty()) {
            return Map.of();
        }
        return manifests.findAllById(digests).stream()
                .flatMap(row -> withdrawal(row).map(found -> Map.entry(row.getDigest(), found)).stream())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static Optional<ReportWithdrawal> withdrawal(ReportPluginManifestEntity row) {
        if (ReportPluginManifestStatus.ofStored(row.getStatus()) != ReportPluginManifestStatus.WITHDRAWN) {
            return Optional.empty();
        }
        return Optional.of(new ReportWithdrawal(row.getWithdrawnAt(), row.getWithdrawnBy(),
                row.getWithdrawalJustification()));
    }
}

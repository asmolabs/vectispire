package com.asmolabs.vectispire.core.reportplugins;

import java.util.List;

/**
 * What this installation says of a document a holder names by its SHA-256 (decision 0035 §4, lot R7).
 *
 * @param sha256 the digest asked about, as 64 lower-case hexadecimal characters
 * @param standing {@code upheld} when at least one production below stands, {@code withdrawn} when every one was
 *     withdrawn, {@code unknown} when there is none to show
 * @param productions the produced runs whose package or file has that digest, newest first — one for a package,
 *     which names its run in its provenance; possibly more for a file, which a deterministic renderer can write
 *     twice. Empty when {@code unknown}: an absent document and one in a project the caller does not see whole are
 *     the same answer
 */
public record ReportDocumentStatusView(
        String sha256, ReportDocumentStanding standing, List<ReportDocumentProduction> productions) {}

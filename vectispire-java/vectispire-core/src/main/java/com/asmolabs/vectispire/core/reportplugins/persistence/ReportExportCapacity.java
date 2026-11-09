package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.util.OptionalLong;

/**
 * How large a value one statement may carry to this database — what bounds the export a produced run keeps in
 * one row of {@code t_report_export}.
 */
public interface ReportExportCapacity {

    /**
     * MySQL's {@code max_allowed_packet}, the largest statement the server accepts and the driver refuses beyond
     * (64 MiB by default); absent on PostgreSQL, whose {@code bytea} holds a gigabyte, far past any export.
     */
    OptionalLong largestStatementBytes();
}

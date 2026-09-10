package com.asmolabs.vectispire.core.repositories;

/**
 * How many issues in a given state one target carries.
 *
 * <p>See {@link LatestScanRow} for why these queries return a record rather than {@code Object[]}.
 *
 * @param targetId the repository or the image, depending on which query produced this
 */
public record OpenIssueCount(Long targetId, Long count) {}

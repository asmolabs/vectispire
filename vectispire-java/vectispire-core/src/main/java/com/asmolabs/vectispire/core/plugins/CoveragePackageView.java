package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.CoveragePackageEntity;

/**
 * One package of an accepted coverage import, under the entity's property names.
 *
 * @param path segments joined by {@code /}, the top level empty
 * @param branchesCovered and {@code branchesTotal}: null when the report counted no branch
 */
public record CoveragePackageView(
        Long id, Long importId, String path, long linesCovered, long linesTotal, Long branchesCovered,
        Long branchesTotal) {

    static CoveragePackageView of(CoveragePackageEntity row) {
        return new CoveragePackageView(row.getId(), row.getImportId(), row.getPath(), row.getLinesCovered(),
                row.getLinesTotal(), row.getBranchesCovered(), row.getBranchesTotal());
    }
}

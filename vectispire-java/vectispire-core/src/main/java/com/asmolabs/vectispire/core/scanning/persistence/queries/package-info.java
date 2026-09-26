/**
 * The projections {@code scanning}'s queries select into that other modules read as they are: {@code
 * LatestScanRow} (the latest scan of each target, for the gate's overview and the compliance
 * evidence) and {@code PackageImpact} (a package's reach across the estate, for the blast radius).
 *
 * <p><b>Published, read-only, and nothing else of {@code persistence}.</b> They are records the
 * database fills and {@code ScanCatalog} hands over unchanged; restating each as an API record would
 * be a second copy to keep in step with the query for no reader's benefit. The entities and the
 * repositories beside them stay the module's own: another module asks {@code ScanCatalog}, never a
 * repository (decision 0029). A controller may not name these either — {@code
 * apiNeverTouchesPersistence} holds for every {@code persistence} package, this one included — and
 * none reaches a route.
 */
@NamedInterface("queries")
package com.asmolabs.vectispire.core.scanning.persistence.queries;

import org.springframework.modulith.NamedInterface;

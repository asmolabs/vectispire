package com.asmolabs.vectispire.core.inventory.persistence;

import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface ComponentRepository extends JpaRepository<ComponentEntity, Long> {

    /**
     * Where a component was seen, newest scan first: the rows, each with its scan's target and
     * creation instant (V61); the scan's branch and project version are {@code ScanCatalog}'s, asked
     * for the few scans the page holds.
     *
     * <p><b>The scan is the answer, not a detail.</b> "Do we ship log4j 2.14.1" is only half a
     * question: what the person asking needs is the release it went out in, so they can say which of
     * their deliveries is affected. The scan carries that — its target and the project version read
     * from the manifest — so the component alone would answer "yes, somewhere, once".
     *
     * <p>Ordered by the copied instant, which is the scan's own {@code createdAt}: the order the join to
     * the scans gave, without naming their table.
     *
     * <p>The version filter is optional and matched exactly: a search for {@code 2.14.1} must not
     * return {@code 2.14.10}, which is a different release with a different verdict. The name is
     * matched loosely, because nobody remembers whether it is {@code log4j-core} or
     * {@code org.apache.logging.log4j:log4j-core}.
     */
    @Query("""
            select c from ComponentEntity c
             where (lower(c.name) like :name or lower(c.purl) like :name)
               and (:version is null or c.version = :version)
             order by c.scanCreatedAt desc, c.name asc""")
    List<ComponentEntity> search(@Param("name") String name, @Param("version") String version, Limit limit);

    /**
     * Every version of one component, <b>with the target it was catalogued on</b>, for the filter
     * the screen offers.
     *
     * <p><b>The join exists so the caller can be filtered, and it was added after the fact.</b>
     * The first version of this query selected {@code distinct c.version} with no join at all, so
     * it answered across the whole estate — a reader given one repository could ask "does anyone
     * here run log4j 2.14.1" and be told. Its sibling {@code search}, four lines above, had
     * filtered from the day it was written; this one had not, and nothing said so because the
     * authorization rule is stated per controller and this controller does resolve a
     * {@code Visibility} — for the other route. The target is the row's own copy of its scan's (V61).
     */
    @Query("""
            select distinct c.version, c.repoId, c.containerId from ComponentEntity c
             where (lower(c.name) like :name or lower(c.purl) like :name)
             order by c.version desc""")
    List<Object[]> versionsOf(@Param("name") String name, Limit limit);

    List<ComponentEntity> findByScanId(long scanId);

    /** Which of these scans the inventory holds components of — the backfill keeps the others. */
    @Query("select distinct c.scanId from ComponentEntity c where c.scanId in :scanIds")
    List<Long> indexedAmong(@Param("scanIds") Collection<Long> scanIds);

    List<ComponentEntity> findByScanIdIn(Collection<Long> scanIds);

    /**
     * The names of these scans' components, in scan and row order — the licence inventory's read.
     *
     * <p><b>Not the entities</b>: the estate's inventory reads every component row of every scan,
     * a hundred thousand for two hundred targets of two scans, and each one entered the persistence
     * context to be dropped at once. <b>Ordered</b>, because of two rows naming one component of one
     * target the first decides the purl the inventory shows: without an order that was whichever row
     * the engine returned first, and a read of five targets could disagree with the estate's.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.inventory.persistence.ComponentName(
                   c.scanId, c.name, c.version, c.purl, c.origin, c.scannedVersion, c.declaredLicense)
              from ComponentEntity c
             where c.scanId in :scanIds
             order by c.scanId, c.id""")
    List<ComponentName> namesOfScans(@Param("scanIds") Collection<Long> scanIds);

    @Transactional
    void deleteByScanId(long scanId);

    /**
     * A scan's rows, locked for the write that completes them with a build SBOM — two imports of one
     * repository completing its newest scan at once would otherwise both add the build's components.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from ComponentEntity c where c.scanId = :scanId order by c.id")
    List<ComponentEntity> lockScan(@Param("scanId") long scanId);

    /**
     * For each of these imports, the newest scan it completed — what an import's history shows. An
     * import that completed none is absent. The caller hands at most a page of imports.
     */
    @Query("""
            select c.buildSbomId, max(c.scanId) from ComponentEntity c
             where c.buildSbomId in :importIds
             group by c.buildSbomId""")
    List<Object[]> newestScanCompletedBy(@Param("importIds") Collection<Long> importIds);

    /**
     * Per repository, how many rows a build SBOM completed and the newest import among them — what the
     * licence tallies compare, beside the scans' census, to know that a target's inventory moved when no
     * scan did. Only build-completed rows are read, through their index.
     */
    @Query("""
            select c.repoId, count(c), max(c.buildSbomId) from ComponentEntity c
             where c.buildSbomId is not null and c.repoId is not null
             group by c.repoId""")
    List<Object[]> buildCompletionByRepository();

    @Transactional
    void deleteByScanIdIn(Collection<Long> scanIds);

    long countByScanIdIn(Collection<Long> scanIds);

    /**
     * The repositories whose scans produced an inventory, and the images likewise.
     *
     * <p><b>Read from the components and not from the {@code sbom} column, and that is the whole
     * point of the pair.</b> The raw payload is purged on the retention window — ninety days by
     * default — so counting targets with a non-empty blob would make the supply-chain control
     * decay over time on an estate where nothing changed. The components are the normalized
     * projection and are never purged, which is what makes "this target has an inventory" a
     * durable fact rather than a property of how recently it was scanned.
     *
     * <p>The target is the row's copy of its scan's (V61): a component goes with its scan, so a target
     * with a component row is one a scan produced an inventory of, as the join to the scans said.
     *
     * <p>Two queries rather than one union: the two id spaces are unrelated, and a union would
     * have to carry a discriminator column that every engine spells differently.
     */
    @Query("""
            select distinct c.repoId from ComponentEntity c where c.repoId is not null""")
    List<Long> distinctRepositoriesWithComponents();

    /** @see #distinctRepositoriesWithComponents() */
    @Query("""
            select distinct c.containerId from ComponentEntity c where c.containerId is not null""")
    List<Long> distinctContainersWithComponents();

    /**
     * Every distinct package-URL type ({@code pkg:npm/}), with the target its scan was of — which
     * ecosystems each target is written in, the question rule coverage asks of the inventory.
     *
     * <p><b>The type, not the purl, and that is the point.</b> A thousand npm dependencies and one are
     * the same answer, and the purl's prefix up to its first slash is everything {@code RuleCoverage}
     * reads of it. This query used to select the distinct purls, on the belief that distinctness kept
     * the result proportional to the ecosystems; it does not, since a purl carries a name and a
     * version: on the 1.0.0-rc.1 load test's estate (300 targets, a million rows) it returned 390,000
     * rows in 1.6 s, paid by the dashboard and the security overview at every call and by the gate at
     * every verdict. {@code purl_type} is that prefix, generated by the database (V96), and its index
     * answers this by a loose scan — one entry per target and type, 1,500 there — in 40 ms.
     *
     * <p><b>One query for the whole estate rather than one per target.</b> The posture screen asks
     * the coverage question of every target it lists; asking the database once per row would make
     * a screen's cost grow with the estate, which is the shape {@code ReadCostSweepTest} exists to
     * refuse. Rows are {@code [repoId, containerId, type]}; a row's repository wins over its image, as
     * the caller keys them.
     */
    @Query("""
            select distinct c.repoId, c.containerId, c.purlType from ComponentEntity c
             where c.purlType is not null""")
    List<Object[]> distinctPurlTypesByTarget();

    /**
     * The package-URL types of one repository's inventory — the gate's question, which is about the
     * target in front of it.
     *
     * <p><b>A query of its own rather than the estate's answer filtered.</b> The gate read the estate's
     * answer — then every purl of the estate — for each verdict and kept one entry: 1.8 s a pipeline
     * call on the load test's estate, against a few milliseconds for this one on the index's prefix.
     */
    @Query("""
            select distinct c.purlType from ComponentEntity c
             where c.repoId = :repoId and c.purlType is not null""")
    List<String> distinctPurlTypesOfRepository(@Param("repoId") long repoId);

    /**
     * The same for one image: the rows naming it and no repository, which is what the estate's answer
     * keys under the image — a row naming both counts for the repository.
     */
    @Query("""
            select distinct c.purlType from ComponentEntity c
             where c.repoId is null and c.containerId = :containerId and c.purlType is not null""")
    List<String> distinctPurlTypesOfContainer(@Param("containerId") long containerId);
}

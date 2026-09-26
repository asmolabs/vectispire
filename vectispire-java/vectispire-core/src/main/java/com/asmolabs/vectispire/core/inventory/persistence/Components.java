package com.asmolabs.vectispire.core.inventory.persistence;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface Components extends JpaRepository<ComponentEntity, Long> {

    /**
     * Where a component was seen, and in which version of which project.
     *
     * <p><b>The join to the scan is the answer, not a detail.</b> "Do we ship log4j 2.14.1" is
     * only half a question: what the person asking needs is the release it went out in, so they
     * can say which of their deliveries is affected. The scan carries that — its target and the
     * project version read from the manifest — so the component alone would answer "yes,
     * somewhere, once".
     *
     * <p>The version filter is optional and matched exactly: a search for {@code 2.14.1} must not
     * return {@code 2.14.10}, which is a different release with a different verdict. The name is
     * matched loosely, because nobody remembers whether it is {@code log4j-core} or
     * {@code org.apache.logging.log4j:log4j-core}.
     */
    @Query("""
            select c, s.id, s.repoId, s.containerId, s.branch, s.version, s.createdAt
              from ComponentEntity c, ScanEntity s
             where c.scanId = s.id
               and (lower(c.name) like :name or lower(c.purl) like :name)
               and (:version is null or c.version = :version)
             order by s.createdAt desc, c.name asc""")
    List<Object[]> search(@Param("name") String name, @Param("version") String version, Limit limit);

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
     * {@code Visibility} — for the other route.
     */
    @Query("""
            select distinct c.version, s.repoId, s.containerId from ComponentEntity c, ScanEntity s
             where c.scanId = s.id
               and (lower(c.name) like :name or lower(c.purl) like :name)
             order by c.version desc""")
    List<Object[]> versionsOf(@Param("name") String name, Limit limit);

    List<ComponentEntity> findByScanId(long scanId);

    List<ComponentEntity> findByScanIdIn(Collection<Long> scanIds);

    void deleteByScanId(long scanId);

    void deleteByScanIdIn(Collection<Long> scanIds);

    long countByScanIdIn(Collection<Long> scanIds);

    /**
     * Every distinct package URL the inventory holds.
     *
     * <p><b>Distinct, and the distinctness is the point.</b> What is being asked is which
     * ecosystems this estate is written in, not how many packages it has — a thousand npm
     * dependencies and one are the same answer to that question, and reading a thousand rows to
     * arrive at it would make a banner cost more than the page it sits on.
     */
    @Query("select distinct c.purl from ComponentEntity c where c.purl is not null")
    List<String> distinctPurls();

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
     * <p>Two queries rather than one union: the two id spaces are unrelated, and a union would
     * have to carry a discriminator column that every engine spells differently.
     */
    @Query("""
            select distinct s.repoId from ComponentEntity c, ScanEntity s
             where c.scanId = s.id and s.repoId is not null""")
    List<Long> distinctRepositoriesWithComponents();

    /** @see #distinctRepositoriesWithComponents() */
    @Query("""
            select distinct s.containerId from ComponentEntity c, ScanEntity s
             where c.scanId = s.id and s.containerId is not null""")
    List<Long> distinctContainersWithComponents();

    /**
     * Every distinct package URL, with the target its scan was of.
     *
     * <p><b>One query for the whole estate rather than one per target.</b> The posture screen asks
     * the coverage question of every target it lists; asking the database once per row would make
     * a screen's cost grow with the estate, which is the shape {@code ReadCostSweepTest} exists to
     * refuse. The rows are grouped in memory, and distinctness keeps the result proportional to
     * the ecosystems rather than to the dependencies.
     *
     * <p>Rows are {@code [repoId, containerId, purl]}; exactly one of the two ids is set, which is
     * the discriminator a union would have had to invent a column for.
     */
    @Query("""
            select distinct s.repoId, s.containerId, c.purl from ComponentEntity c, ScanEntity s
             where c.scanId = s.id and c.purl is not null""")
    List<Object[]> distinctPurlsByTarget();
}

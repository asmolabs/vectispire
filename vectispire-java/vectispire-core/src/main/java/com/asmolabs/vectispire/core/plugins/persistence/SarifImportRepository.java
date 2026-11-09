package com.asmolabs.vectispire.core.plugins.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The accepted SARIF imports. */
public interface SarifImportRepository extends JpaRepository<SarifImportEntity, Long> {

    List<SarifImportEntity> findByRepoIdOrderByImportedAtDescIdDesc(long repoId, Pageable page);

    /**
     * The newest import of each repository named whose accepted tools include the one {@code pattern}
     * matches — {@code %,<key>,%} over the keys wrapped in commas, {@code !} escaping the key's own
     * {@code %}, {@code _} and {@code !}. An import from before {@code tool_keys} concatenates to null on
     * every engine and matches nothing. Newest by id. The caller batches the ids.
     */
    @Query("select i from SarifImportEntity i where i.repoId in :repositoryIds and i.id = "
            + "(select max(o.id) from SarifImportEntity o where o.repoId = i.repoId "
            + "and concat(',', o.toolKeys, ',') like :pattern escape '!')")
    List<SarifImportEntity> findNewestCarrying(
            @Param("repositoryIds") Collection<Long> repositoryIds, @Param("pattern") String pattern);

    /**
     * The repositories among these holding an import from the source, at or after {@code since}, that
     * recorded no tool keys — accepted before the record existed.
     */
    @Query("select distinct i.repoId from SarifImportEntity i where i.repoId in :repositoryIds "
            + "and i.sourceSlug = :sourceSlug and i.importedAt >= :since and i.toolKeys is null")
    List<Long> findUnrecordedSince(
            @Param("repositoryIds") Collection<Long> repositoryIds, @Param("sourceSlug") String sourceSlug,
            @Param("since") Instant since);

    /** A repository's imports, when the repository goes — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from SarifImportEntity i where i.repoId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}

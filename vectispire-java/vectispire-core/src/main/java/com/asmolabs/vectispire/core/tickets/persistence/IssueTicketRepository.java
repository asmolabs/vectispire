package com.asmolabs.vectispire.core.tickets.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Access to external ticket mappings.
 */
@Repository
public interface IssueTicketRepository extends JpaRepository<IssueTicketEntity, Long> {

    List<IssueTicketEntity> findByIssueIdOrderByCreatedAtDescIdDesc(Long issueId);

    @Transactional
    void deleteByIssueIdIn(java.util.Collection<Long> issueIds);
}

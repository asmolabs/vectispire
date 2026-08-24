package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.IssueTicketEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Access to external ticket mappings.
 */
@Repository
public interface IssueTickets extends JpaRepository<IssueTicketEntity, Long> {

    List<IssueTicketEntity> findByIssueIdOrderByCreatedAtDesc(Long issueId);

    Optional<IssueTicketEntity> findByIssueIdAndProvider(Long issueId, String provider);

    void deleteByIssueIdIn(java.util.Collection<Long> issueIds);
}

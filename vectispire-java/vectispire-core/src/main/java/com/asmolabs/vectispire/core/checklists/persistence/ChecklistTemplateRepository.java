package com.asmolabs.vectispire.core.checklists.persistence;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** The organisation's checklist templates, each under its slug. */
public interface ChecklistTemplateRepository extends JpaRepository<ChecklistTemplateEntity, Long> {

    Optional<ChecklistTemplateEntity> findBySlug(String slug);

    List<ChecklistTemplateEntity> findAllByOrderBySlugAsc();
}

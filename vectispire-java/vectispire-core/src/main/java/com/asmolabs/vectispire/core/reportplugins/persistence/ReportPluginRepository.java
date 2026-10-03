package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

/** The registered report plugins. */
public interface ReportPluginRepository extends JpaRepository<ReportPluginEntity, String> {

    List<ReportPluginEntity> findAllByOrderByIdAsc();
}

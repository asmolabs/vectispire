package com.asmolabs.zanshin.repository.entities;

import com.asmolabs.zanshin.container.entities.Container;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;

@Entity
@Table(name = "scan")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String branch;

    @Builder.Default
    @Column(name = "sub_path")
    private String subPath = "";

    @Builder.Default
    @Column(nullable = false)
    private String status = "pending";

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> sbom;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> cves;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> summary;

    private Long durationMs;

    @Builder.Default
    @Column(nullable = false)
    private int findingsCount = 0;

    private String error;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private String version;

    private String projectType;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repo_id")
    private ZanshinRepository repository;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "container_id")
    private Container container;
}

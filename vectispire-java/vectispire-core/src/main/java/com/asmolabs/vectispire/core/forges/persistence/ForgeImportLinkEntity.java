package com.asmolabs.vectispire.core.forges.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Where an imported repository target came from (decision 0037 §5): the connection, the forge's own id and the
 * discovery whose snapshot the import read. No foreign key to the target, which is another module's row: the link
 * goes with the target through {@code TargetDeleted}, and with the connection when it is deleted.
 */
@Entity
@Table(name = "t_forge_import_link")
public class ForgeImportLinkEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "repository_id", nullable = false)
    private Long repositoryId;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "connection_id", nullable = false)
    private UUID connectionId;

    @Column(name = "forge_id", length = 64, nullable = false)
    private String forgeId;

    @Column(name = "discovery_id", nullable = false)
    private Long discoveryId;

    @Column(name = "imported_at", nullable = false)
    private Instant importedAt;

    @Column(name = "imported_by", length = 255, nullable = false)
    private String importedBy;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getRepositoryId() {
        return repositoryId;
    }

    public void setRepositoryId(Long repositoryId) {
        this.repositoryId = repositoryId;
    }

    public UUID getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(UUID connectionId) {
        this.connectionId = connectionId;
    }

    public String getForgeId() {
        return forgeId;
    }

    public void setForgeId(String forgeId) {
        this.forgeId = forgeId;
    }

    public Long getDiscoveryId() {
        return discoveryId;
    }

    public void setDiscoveryId(Long discoveryId) {
        this.discoveryId = discoveryId;
    }

    public Instant getImportedAt() {
        return importedAt;
    }

    public void setImportedAt(Instant importedAt) {
        this.importedAt = importedAt;
    }

    public String getImportedBy() {
        return importedBy;
    }

    public void setImportedBy(String importedBy) {
        this.importedBy = importedBy;
    }
}

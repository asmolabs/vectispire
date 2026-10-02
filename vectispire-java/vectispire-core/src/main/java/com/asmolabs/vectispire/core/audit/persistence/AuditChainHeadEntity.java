package com.asmolabs.vectispire.core.audit.persistence;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * The single row an audit entry locks before it chains onto the log's head — see V66 and
 * {@link AuditChainHeadRepository#lock}. It carries nothing: the head is the newest entry, read
 * under the lock, and a copy here would be a second answer to "what is the head".
 */
@Entity
@Table(name = "t_audit_chain_head")
public class AuditChainHeadEntity {

    /** The one row's identifier, inserted by V66. */
    public static final int THE_ROW = 1;

    @Id
    private Integer id;

    protected AuditChainHeadEntity() {}

    public Integer getId() {
        return id;
    }
}

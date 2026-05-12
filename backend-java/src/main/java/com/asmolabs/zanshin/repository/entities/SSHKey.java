package com.asmolabs.zanshin.repository.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "ssh_key")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SSHKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(name = "private_key", columnDefinition = "TEXT", nullable = false)
    private String privateKey;

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "sshKey")
    private List<ZanshinRepository> repositories;
}

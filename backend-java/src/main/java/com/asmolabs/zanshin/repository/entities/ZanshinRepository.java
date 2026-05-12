package com.asmolabs.zanshin.repository.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "repository", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"url", "branch", "sub_path"})
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ZanshinRepository {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String url;

    @Column(nullable = false)
    private String branch = "main";

    @Column(name = "sub_path")
    private String subPath = "";

    private String name;

    @OneToMany(mappedBy = "repository", cascade = CascadeType.ALL)
    private List<Scan> scans;

    @OneToMany(mappedBy = "repository", cascade = CascadeType.ALL)
    private List<VexDecision> vexDecisions;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ssh_key_id")
    private SSHKey sshKey;

    private Integer scanIntervalMinutes;

    private LocalDateTime lastScheduledScanAt;

    private String scanCron;
}

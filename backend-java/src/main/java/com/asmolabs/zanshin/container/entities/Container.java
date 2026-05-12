package com.asmolabs.zanshin.container.entities;

import com.asmolabs.zanshin.repository.entities.Scan;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "container", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"registry", "image_name", "tag"})
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Container {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String registry;

    @Column(name = "image_name", nullable = false)
    private String imageName;

    @Column(nullable = false)
    private String tag = "latest";

    @OneToMany(mappedBy = "container")
    private List<Scan> scans;

    private Integer scanIntervalMinutes;

    private String scanCron;

    private LocalDateTime lastScheduledScanAt;
}

package com.asmolabs.zanshin.settings.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "setting")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Setting {

    @Id
    @Column(name = "key")
    private String key;

    @Column(name = "value")
    private String value;
}

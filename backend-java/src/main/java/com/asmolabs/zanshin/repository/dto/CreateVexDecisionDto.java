package com.asmolabs.zanshin.repository.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CreateVexDecisionDto(
    @NotBlank String vulnerabilityId,
    @NotBlank String packageName,
    String purl,
    @NotBlank String status,
    String justification,
    String response,
    String comment,
    @NotNull Long repositoryId
) {}

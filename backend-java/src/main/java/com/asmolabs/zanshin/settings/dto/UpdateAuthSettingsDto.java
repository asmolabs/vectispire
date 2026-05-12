package com.asmolabs.zanshin.settings.dto;

public record UpdateAuthSettingsDto(
    Boolean githubEnabled,
    Boolean keycloakEnabled
) {}

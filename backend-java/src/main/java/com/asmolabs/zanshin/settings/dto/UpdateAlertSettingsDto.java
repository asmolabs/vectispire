package com.asmolabs.zanshin.settings.dto;

public record UpdateAlertSettingsDto(
    String alertEmails,
    String alertMinSeverity
) {}

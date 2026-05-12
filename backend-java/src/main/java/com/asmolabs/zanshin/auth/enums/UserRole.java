package com.asmolabs.zanshin.auth.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserRole {
    SUPERUSER("superuser"),
    ADMIN("admin"),
    USER("user");

    private final String value;
}

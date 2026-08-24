package com.asmolabs.vectispire.core.api.scim;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.api.scim.dto.ScimListResponse;
import com.asmolabs.vectispire.core.api.scim.dto.ScimPatchOp;
import com.asmolabs.vectispire.core.api.scim.dto.ScimUserDto;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.BooleanNode;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@DisplayName("SCIM Users Controller")
class ScimUsersControllerTest {

    private Users users;
    private AuthService auth;
    private AuditLogService audit;
    private Clock clock;
    private ScimUsersController controller;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        users = mock(Users.class);
        auth = mock(AuthService.class);
        audit = mock(AuditLogService.class);
        clock = Clock.fixed(Instant.parse("2026-08-22T10:00:00Z"), ZoneOffset.UTC);
        controller = new ScimUsersController(users, auth, audit, clock);
        request = mock(HttpServletRequest.class);
    }

    @Test
    @DisplayName("provisions a new user with active state and random hashed password")
    void provisionsNewUser() {
        when(users.findByUsername("alice")).thenReturn(Optional.empty());
        when(users.save(any(UserEntity.class))).thenAnswer(inv -> {
            UserEntity u = inv.getArgument(0);
            u.setId(101L);
            return u;
        });

        ScimUserDto requestDto = new ScimUserDto(
                List.of(ScimUserDto.SCHEMA_USER),
                null,
                "ext-alice-123",
                "alice",
                new ScimUserDto.Name("Alice Smith", "Smith", "Alice"),
                "Alice Smith",
                List.of(new ScimUserDto.Email("alice@example.com", "work", true)),
                List.of(new ScimUserDto.RoleEntry("USER", true)),
                true,
                null);

        ResponseEntity<ScimUserDto> response = controller.createUser(requestDto, request);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().userName()).isEqualTo("alice");
        assertThat(response.getBody().id()).isEqualTo("101");
        assertThat(response.getBody().active()).isTrue();
    }

    @Test
    @DisplayName("deactivating a user revokes all active sessions immediately")
    void deactivatingUserRevokesSessions() {
        UserEntity existing = new UserEntity();
        existing.setId(42L);
        existing.setUsername("bob");
        existing.setIsActive(true);

        when(users.findById(42L)).thenReturn(Optional.of(existing));
        when(users.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        ScimPatchOp patch = new ScimPatchOp(
                List.of(ScimPatchOp.SCHEMA_PATCH),
                List.of(new ScimPatchOp.PatchOperation("replace", "active", BooleanNode.FALSE)));

        ResponseEntity<ScimUserDto> response = controller.patchUser(42L, patch, request);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().active()).isFalse();

        // Critical security requirement: active sessions must be terminated
        verify(auth).revokeAllForUser(42L);
    }

    @Test
    @DisplayName("filters users by userName")
    void filtersUsersByUserName() {
        UserEntity user = new UserEntity();
        user.setId(7L);
        user.setUsername("charlie");
        user.setIsActive(true);

        when(users.findByUsername("charlie")).thenReturn(Optional.of(user));

        ScimListResponse<ScimUserDto> result = controller.listUsers("userName eq \"charlie\"", 1, 10);
        assertThat(result.totalResults()).isEqualTo(1);
        assertThat(result.resources().get(0).userName()).isEqualTo("charlie");
    }
}

package com.asmolabs.zanshin.core.api.scim;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.crypto.PasswordHasher;
import com.asmolabs.zanshin.common.domain.users.AccountRules;
import com.asmolabs.zanshin.common.domain.users.Role;
import com.asmolabs.zanshin.core.api.scim.dto.ScimErrorResponse;
import com.asmolabs.zanshin.core.api.scim.dto.ScimListResponse;
import com.asmolabs.zanshin.core.api.scim.dto.ScimPatchOp;
import com.asmolabs.zanshin.core.api.scim.dto.ScimUserDto;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.Users;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.AuthService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.asmolabs.zanshin.core.api.security.RequiresAdministrator;

/**
 * SCIM 2.0 /Users endpoint (RFC 7644 Section 3.2).
 *
 * <p>Enables identity providers (Okta, Entra ID, Ping) to provision and deprovision users,
 * and revoke sessions immediately when an account is deactivated.
 */
@RestController
@RequestMapping(value = "/scim/v2/Users", produces = "application/scim+json")
@RequiresAdministrator
public class ScimUsersController {

    private static final Logger log = LoggerFactory.getLogger(ScimUsersController.class);

    private final Users users;
    private final AuthService auth;
    private final AuditLogService audit;
    private final Clock clock;

    public ScimUsersController(Users users, AuthService auth, AuditLogService audit, Clock clock) {
        this.users = users;
        this.auth = auth;
        this.audit = audit;
        this.clock = clock;
    }

    @GetMapping
    public ScimListResponse<ScimUserDto> listUsers(
            @RequestParam(required = false) String filter,
            @RequestParam(defaultValue = "1") int startIndex,
            @RequestParam(defaultValue = "100") int count) {

        List<UserEntity> matched;
        if (filter != null && !filter.isBlank()) {
            matched = filterUsers(filter.trim());
        } else {
            matched = users.findAllByOrderByUsernameAsc();
        }

        List<ScimUserDto> resources = matched.stream().map(this::toDto).toList();
        return ScimListResponse.of(resources);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScimUserDto> getUser(@PathVariable Long id) {
        return users.findById(id)
                .map(u -> ResponseEntity.ok(toDto(u)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PostMapping(consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimUserDto> createUser(
            @RequestBody ScimUserDto dto, HttpServletRequest request) {

        String username = dto.userName() == null ? "" : dto.userName().trim().toLowerCase(Locale.ROOT);
        AccountRules.validateUsername(username).ifPresent(msg -> {
            throw new IllegalArgumentException(msg);
        });

        if (users.findByUsername(username).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        Instant now = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setDisplayName(extractDisplayName(dto));
        user.setEmail(extractEmail(dto));
        user.setKeycloakId(dto.externalId());
        user.setIsActive(dto.active() == null || dto.active());
        user.setRole(extractRole(dto));
        user.setPassword(PasswordHasher.hash(UUID.randomUUID().toString()));
        user.setMustChangePassword(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);

        UserEntity saved = users.save(user);

        audit.record(new AuditLogService.Record(
                AuditOperation.USER_CREATED,
                "SCIM",
                "SCIM provisioned account: " + username,
                username,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        ScimUserDto responseDto = toDto(saved);
        return ResponseEntity.created(URI.create("/scim/v2/Users/" + saved.getId())).body(responseDto);
    }

    @PutMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimUserDto> updateUser(
            @PathVariable Long id, @RequestBody ScimUserDto dto, HttpServletRequest request) {

        Optional<UserEntity> found = users.findById(id);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        UserEntity user = found.get();
        boolean wasActive = Boolean.TRUE.equals(user.getIsActive());
        boolean nowActive = dto.active() == null || dto.active();

        user.setDisplayName(extractDisplayName(dto));
        user.setEmail(extractEmail(dto));
        if (dto.externalId() != null) {
            user.setKeycloakId(dto.externalId());
        }
        user.setIsActive(nowActive);
        user.setRole(extractRole(dto));
        user.setUpdatedAt(clock.instant());

        UserEntity saved = users.save(user);

        // Immediate session deprovisioning upon deactivation
        if (wasActive && !nowActive) {
            auth.revokeAllForUser(saved.getId());
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    "SCIM",
                    "SCIM deactivated account and revoked all active sessions for " + saved.getUsername(),
                    saved.getUsername(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        } else {
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    "SCIM",
                    "SCIM updated account: " + saved.getUsername(),
                    saved.getUsername(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        }

        return ResponseEntity.ok(toDto(saved));
    }

    @PatchMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimUserDto> patchUser(
            @PathVariable Long id, @RequestBody ScimPatchOp patch, HttpServletRequest request) {

        Optional<UserEntity> found = users.findById(id);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        UserEntity user = found.get();
        boolean wasActive = Boolean.TRUE.equals(user.getIsActive());

        if (patch.operations() != null) {
            for (ScimPatchOp.PatchOperation op : patch.operations()) {
                applyPatch(user, op);
            }
        }
        user.setUpdatedAt(clock.instant());
        UserEntity saved = users.save(user);

        boolean nowActive = Boolean.TRUE.equals(saved.getIsActive());
        if (wasActive && !nowActive) {
            auth.revokeAllForUser(saved.getId());
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    "SCIM",
                    "SCIM deactivated account and revoked active sessions for " + saved.getUsername(),
                    saved.getUsername(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        }

        return ResponseEntity.ok(toDto(saved));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteUser(@PathVariable Long id, HttpServletRequest request) {
        users.findById(id).ifPresent(user -> {
            auth.revokeAllForUser(user.getId());
            users.delete(user);
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_DELETED,
                    "SCIM",
                    "SCIM deleted account: " + user.getUsername(),
                    user.getUsername(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        });
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ScimErrorResponse> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ScimErrorResponse.of(HttpStatus.BAD_REQUEST.value(), ex.getMessage()));
    }

    private void applyPatch(UserEntity user, ScimPatchOp.PatchOperation op) {
        String path = op.path() == null ? "" : op.path().toLowerCase(Locale.ROOT);
        JsonNode value = op.value();

        if ("active".equals(path) && value != null && value.isBoolean()) {
            user.setIsActive(value.asBoolean());
        } else if (value != null && value.isObject()) {
            if (value.has("active") && value.get("active").isBoolean()) {
                user.setIsActive(value.get("active").asBoolean());
            }
            if (value.has("displayName") && value.get("displayName").isTextual()) {
                user.setDisplayName(value.get("displayName").asText());
            }
        }
    }

    private List<UserEntity> filterUsers(String filter) {
        // Basic SCIM filter parser: supports `userName eq "val"` or `externalId eq "val"`
        String[] parts = filter.split("\\s+eq\\s+", 2);
        if (parts.length == 2) {
            String attr = parts[0].trim().toLowerCase(Locale.ROOT);
            String val = parts[1].trim().replaceAll("^\"|\"$", "");
            if ("username".equals(attr)) {
                return users.findByUsername(val.toLowerCase(Locale.ROOT)).map(List::of).orElse(List.of());
            } else if ("externalid".equals(attr)) {
                return users.findByKeycloakId(val).map(List::of).orElse(List.of());
            }
        }
        return users.findAllByOrderByUsernameAsc();
    }

    private ScimUserDto toDto(UserEntity user) {
        List<ScimUserDto.Email> emails = user.getEmail() != null && !user.getEmail().isBlank()
                ? List.of(new ScimUserDto.Email(user.getEmail(), "work", true))
                : List.of();
        List<ScimUserDto.RoleEntry> roles = user.getRole() != null
                ? List.of(new ScimUserDto.RoleEntry(user.getRole(), true))
                : List.of();

        ScimUserDto.Meta meta = new ScimUserDto.Meta(
                "User",
                user.getCreatedAt() != null ? user.getCreatedAt().toString() : null,
                user.getUpdatedAt() != null ? user.getUpdatedAt().toString() : null,
                "/scim/v2/Users/" + user.getId());

        return new ScimUserDto(
                List.of(ScimUserDto.SCHEMA_USER),
                String.valueOf(user.getId()),
                user.getKeycloakId(),
                user.getUsername(),
                new ScimUserDto.Name(user.getDisplayName(), null, null),
                user.getDisplayName(),
                emails,
                roles,
                user.getIsActive(),
                meta);
    }

    private static String extractDisplayName(ScimUserDto dto) {
        if (dto.displayName() != null && !dto.displayName().isBlank()) {
            return dto.displayName().trim();
        }
        if (dto.name() != null && dto.name().formatted() != null && !dto.name().formatted().isBlank()) {
            return dto.name().formatted().trim();
        }
        return null;
    }

    private static String extractEmail(ScimUserDto dto) {
        if (dto.emails() != null && !dto.emails().isEmpty()) {
            return dto.emails().get(0).value();
        }
        return null;
    }

    private static String extractRole(ScimUserDto dto) {
        if (dto.roles() != null && !dto.roles().isEmpty()) {
            String val = dto.roles().get(0).value();
            if (val != null && Role.of(val.toUpperCase(Locale.ROOT)).isPresent()) {
                return val.toUpperCase(Locale.ROOT);
            }
        }
        return Role.USER.name();
    }
}

package com.asmolabs.vectispire.core.access.web.scim;

import com.asmolabs.vectispire.core.access.ScimProvisioningService;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimErrorResponse;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimListResponse;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimPatchOp;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimUserDto;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
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

    private final ScimProvisioningService provisioning;

    public ScimUsersController(ScimProvisioningService provisioning) {
        this.provisioning = provisioning;
    }

    @GetMapping
    public ScimListResponse<ScimUserDto> listUsers(
            @RequestParam(required = false) String filter,
            @RequestParam(defaultValue = "1") int startIndex,
            @RequestParam(defaultValue = "100") int count) {

        List<ScimUserDto> resources = provisioning.users(filter).stream().map(ScimUsersController::toDto).toList();
        return ScimListResponse.of(resources);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScimUserDto> getUser(@PathVariable Long id) {
        return provisioning.user(id)
                .map(u -> ResponseEntity.ok(toDto(u)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PostMapping(consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimUserDto> createUser(
            @RequestBody ScimUserDto dto, HttpServletRequest request) {

        return switch (provisioning.createUser(attributesOf(dto), RequestActors.unnamed(request))) {
            case ScimProvisioningService.UserCreation.UsernameTaken taken ->
                    ResponseEntity.status(HttpStatus.CONFLICT).build();
            case ScimProvisioningService.UserCreation.Created(UserView saved) ->
                    ResponseEntity.created(URI.create("/scim/v2/Users/" + saved.id())).body(toDto(saved));
        };
    }

    @PutMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimUserDto> updateUser(
            @PathVariable Long id, @RequestBody ScimUserDto dto, HttpServletRequest request) {

        return provisioning.replaceUser(id, attributesOf(dto), RequestActors.unnamed(request))
                .map(saved -> ResponseEntity.ok(toDto(saved)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PatchMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimUserDto> patchUser(
            @PathVariable Long id, @RequestBody ScimPatchOp patch, HttpServletRequest request) {

        return provisioning.patchUser(id, operationsOf(patch), RequestActors.unnamed(request))
                .map(saved -> ResponseEntity.ok(toDto(saved)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteUser(@PathVariable Long id, HttpServletRequest request) {
        provisioning.deleteUser(id, RequestActors.unnamed(request));
    }

    /** 403 rather than 404: the account exists and the directory may read it, only not change it. */
    @ExceptionHandler(ScimProvisioningService.ProtectedAccountException.class)
    public ResponseEntity<ScimErrorResponse> handleProtected(ScimProvisioningService.ProtectedAccountException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ScimErrorResponse.of(HttpStatus.FORBIDDEN.value(), ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ScimErrorResponse> handleBadInput(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ScimErrorResponse.of(HttpStatus.BAD_REQUEST.value(), ex.getMessage()));
    }

    static List<ScimProvisioningService.PatchOperation> operationsOf(ScimPatchOp patch) {
        return patch.operations() == null
                ? null
                : patch.operations().stream()
                        .map(op -> new ScimProvisioningService.PatchOperation(op.op(), op.path(), op.value()))
                        .toList();
    }

    private static ScimProvisioningService.UserAttributes attributesOf(ScimUserDto dto) {
        return new ScimProvisioningService.UserAttributes(
                dto.userName(),
                displayNameOf(dto),
                emailOf(dto),
                dto.externalId(),
                dto.active(),
                dto.roles() != null && !dto.roles().isEmpty() ? dto.roles().get(0).value() : null);
    }

    private static ScimUserDto toDto(UserView user) {
        List<ScimUserDto.Email> emails = user.email() != null && !user.email().isBlank()
                ? List.of(new ScimUserDto.Email(user.email(), "work", true))
                : List.of();
        List<ScimUserDto.RoleEntry> roles = user.role() != null
                ? List.of(new ScimUserDto.RoleEntry(user.role(), true))
                : List.of();

        ScimUserDto.ScimUserMeta meta = new ScimUserDto.ScimUserMeta(
                "User",
                user.createdAt() != null ? user.createdAt().toString() : null,
                user.updatedAt() != null ? user.updatedAt().toString() : null,
                "/scim/v2/Users/" + user.id());

        return new ScimUserDto(
                List.of(ScimUserDto.SCHEMA_USER),
                String.valueOf(user.id()),
                user.keycloakId(),
                user.username(),
                new ScimUserDto.Name(user.displayName(), null, null),
                user.displayName(),
                emails,
                roles,
                user.isActive(),
                meta);
    }

    /** SCIM carries the name in two places; the flat one wins when both are there. */
    private static String displayNameOf(ScimUserDto dto) {
        if (dto.displayName() != null && !dto.displayName().isBlank()) {
            return dto.displayName().trim();
        }
        if (dto.name() != null && dto.name().formatted() != null && !dto.name().formatted().isBlank()) {
            return dto.name().formatted().trim();
        }
        return null;
    }

    private static String emailOf(ScimUserDto dto) {
        if (dto.emails() != null && !dto.emails().isEmpty()) {
            return dto.emails().get(0).value();
        }
        return null;
    }
}

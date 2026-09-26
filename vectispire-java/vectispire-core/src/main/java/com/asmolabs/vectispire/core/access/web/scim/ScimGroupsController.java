package com.asmolabs.vectispire.core.access.web.scim;

import com.asmolabs.vectispire.core.access.ScimProvisioningService;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimGroupDto;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimListResponse;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimPatchOp;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * SCIM 2.0 /Groups endpoint (RFC 7644 Section 3.2).
 *
 * <p>Enables identity providers to synchronize corporate teams and assign members automatically.
 * The memberships it writes are marked as SCIM's — see {@link ScimProvisioningService} for why.
 */
@RestController
@RequestMapping(value = "/scim/v2/Groups", produces = "application/scim+json")
@RequiresAdministrator
public class ScimGroupsController {

    private final ScimProvisioningService provisioning;

    public ScimGroupsController(ScimProvisioningService provisioning) {
        this.provisioning = provisioning;
    }

    @GetMapping
    public ScimListResponse<ScimGroupDto> listGroups() {
        return ScimListResponse.of(provisioning.groups().stream().map(ScimGroupsController::toDto).toList());
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScimGroupDto> getGroup(@PathVariable Long id) {
        return provisioning.group(id)
                .map(group -> ResponseEntity.ok(toDto(group)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PostMapping(consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimGroupDto> createGroup(@RequestBody ScimGroupDto dto, HttpServletRequest request) {
        return switch (provisioning.createGroup(dto.displayName(), memberValuesOf(dto), RequestActors.unnamed(request))) {
            case ScimProvisioningService.GroupCreation.NameTaken taken ->
                    ResponseEntity.status(HttpStatus.CONFLICT).build();
            case ScimProvisioningService.GroupCreation.Created(ScimProvisioningService.GroupView group) ->
                    ResponseEntity.created(URI.create("/scim/v2/Groups/" + group.id())).body(toDto(group));
        };
    }

    @PutMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimGroupDto> updateGroup(
            @PathVariable Long id, @RequestBody ScimGroupDto dto, HttpServletRequest request) {

        return provisioning.replaceGroup(id, dto.displayName(), memberValuesOf(dto), RequestActors.unnamed(request))
                .map(group -> ResponseEntity.ok(toDto(group)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @PatchMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    public ResponseEntity<ScimGroupDto> patchGroup(
            @PathVariable Long id, @RequestBody ScimPatchOp patch, HttpServletRequest request) {

        return provisioning.patchGroup(id, ScimUsersController.operationsOf(patch), RequestActors.unnamed(request))
                .map(group -> ResponseEntity.ok(toDto(group)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteGroup(@PathVariable Long id, HttpServletRequest request) {
        provisioning.deleteGroup(id, RequestActors.unnamed(request));
    }

    private static List<String> memberValuesOf(ScimGroupDto dto) {
        return dto.members() == null ? null : dto.members().stream().map(ScimGroupDto.Member::value).toList();
    }

    private static ScimGroupDto toDto(ScimProvisioningService.GroupView group) {
        List<ScimGroupDto.Member> memberDtos = group.members().stream()
                .map(member -> new ScimGroupDto.Member(
                        String.valueOf(member.userId()),
                        member.display(),
                        "/scim/v2/Users/" + member.userId()))
                .toList();

        ScimGroupDto.ScimGroupMeta meta = new ScimGroupDto.ScimGroupMeta(
                "Group",
                group.createdAt() != null ? group.createdAt().toString() : null,
                null,
                "/scim/v2/Groups/" + group.id());

        return new ScimGroupDto(
                List.of(ScimGroupDto.SCHEMA_GROUP),
                String.valueOf(group.id()),
                null,
                group.name(),
                memberDtos,
                meta);
    }
}

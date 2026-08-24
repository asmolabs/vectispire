package com.asmolabs.vectispire.core.api.scim;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.api.scim.dto.ScimGroupDto;
import com.asmolabs.vectispire.core.api.scim.dto.ScimListResponse;
import com.asmolabs.vectispire.core.api.scim.dto.ScimPatchOp;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
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

import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;

/**
 * SCIM 2.0 /Groups endpoint (RFC 7644 Section 3.2).
 *
 * <p>Enables identity providers to synchronize corporate teams and assign members automatically.
 */
@RestController
@RequestMapping(value = "/scim/v2/Groups", produces = "application/scim+json")
@RequiresAdministrator
public class ScimGroupsController {

    private final Teams teams;
    private final TeamMembers members;
    private final Users users;
    private final AuditLogService audit;
    private final Clock clock;

    public ScimGroupsController(
            Teams teams, TeamMembers members, Users users, AuditLogService audit, Clock clock) {
        this.teams = teams;
        this.members = members;
        this.users = users;
        this.audit = audit;
        this.clock = clock;
    }

    @GetMapping
    public ScimListResponse<ScimGroupDto> listGroups() {
        List<TeamEntity> allTeams = teams.findAll();
        Map<Long, UserEntity> userMap = users.findAll().stream()
                .collect(Collectors.toMap(UserEntity::getId, u -> u));

        List<ScimGroupDto> dtos = allTeams.stream()
                .map(t -> toDto(t, members.findByTeamId(t.getId()), userMap))
                .toList();

        return ScimListResponse.of(dtos);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScimGroupDto> getGroup(@PathVariable Long id) {
        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        Map<Long, UserEntity> userMap = users.findAll().stream()
                .collect(Collectors.toMap(UserEntity::getId, u -> u));
        List<TeamMemberEntity> teamMembers = members.findByTeamId(id);
        return ResponseEntity.ok(toDto(found.get(), teamMembers, userMap));
    }

    @PostMapping(consumes = {"application/scim+json", "application/json"})
    @Transactional
    public ResponseEntity<ScimGroupDto> createGroup(@RequestBody ScimGroupDto dto, HttpServletRequest request) {
        String name = dto.displayName() == null ? "" : dto.displayName().trim();
        if (name.isBlank()) {
            throw new IllegalArgumentException("Group displayName cannot be blank.");
        }

        if (teams.findByNameIgnoreCase(name).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        Instant now = clock.instant();
        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setDescription("Created via SCIM");
        team.setCreatedAt(now);
        TeamEntity saved = teams.save(team);

        if (dto.members() != null) {
            for (ScimGroupDto.Member m : dto.members()) {
                resolveUserId(m.value()).ifPresent(userId ->
                        members.save(new TeamMemberEntity(saved.getId(), userId)));
            }
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED,
                "SCIM",
                "SCIM created team: " + name,
                name,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        Map<Long, UserEntity> userMap = users.findAll().stream()
                .collect(Collectors.toMap(UserEntity::getId, u -> u));
        List<TeamMemberEntity> teamMembers = members.findByTeamId(saved.getId());
        return ResponseEntity.created(URI.create("/scim/v2/Groups/" + saved.getId()))
                .body(toDto(saved, teamMembers, userMap));
    }

    @PutMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    @Transactional
    public ResponseEntity<ScimGroupDto> updateGroup(
            @PathVariable Long id, @RequestBody ScimGroupDto dto, HttpServletRequest request) {

        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        TeamEntity team = found.get();
        if (dto.displayName() != null && !dto.displayName().isBlank()) {
            team.setName(dto.displayName().trim());
            teams.save(team);
        }

        // Replace members
        members.deleteByTeamId(id);
        if (dto.members() != null) {
            for (ScimGroupDto.Member m : dto.members()) {
                resolveUserId(m.value()).ifPresent(userId ->
                        members.save(new TeamMemberEntity(id, userId)));
            }
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED,
                "SCIM",
                "SCIM updated team: " + team.getName(),
                team.getName(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        Map<Long, UserEntity> userMap = users.findAll().stream()
                .collect(Collectors.toMap(UserEntity::getId, u -> u));
        List<TeamMemberEntity> teamMembers = members.findByTeamId(id);
        return ResponseEntity.ok(toDto(team, teamMembers, userMap));
    }

    @PatchMapping(value = "/{id}", consumes = {"application/scim+json", "application/json"})
    @Transactional
    public ResponseEntity<ScimGroupDto> patchGroup(
            @PathVariable Long id, @RequestBody ScimPatchOp patch, HttpServletRequest request) {

        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        TeamEntity team = found.get();
        if (patch.operations() != null) {
            for (ScimPatchOp.PatchOperation op : patch.operations()) {
                String opType = op.op() == null ? "" : op.op().toLowerCase(Locale.ROOT);
                if ("add".equals(opType) || "replace".equals(opType)) {
                    handleAddMembers(id, op.value());
                } else if ("remove".equals(opType)) {
                    handleRemoveMembers(id, op);
                }
            }
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED,
                "SCIM",
                "SCIM patched team: " + team.getName(),
                team.getName(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        Map<Long, UserEntity> userMap = users.findAll().stream()
                .collect(Collectors.toMap(UserEntity::getId, u -> u));
        List<TeamMemberEntity> teamMembers = members.findByTeamId(id);
        return ResponseEntity.ok(toDto(team, teamMembers, userMap));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void deleteGroup(@PathVariable Long id, HttpServletRequest request) {
        teams.findById(id).ifPresent(team -> {
            members.deleteByTeamId(id);
            teams.delete(team);
            audit.record(new AuditLogService.Record(
                    AuditOperation.TEAM_UPDATED,
                    "SCIM",
                    "SCIM deleted team: " + team.getName(),
                    team.getName(),
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")));
        });
    }

    private void handleAddMembers(Long teamId, JsonNode value) {
        if (value == null) return;
        if (value.isArray()) {
            for (JsonNode item : value) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asText()).ifPresent(userId ->
                            members.save(new TeamMemberEntity(teamId, userId)));
                }
            }
        } else if (value.isObject() && value.has("members") && value.get("members").isArray()) {
            for (JsonNode item : value.get("members")) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asText()).ifPresent(userId ->
                            members.save(new TeamMemberEntity(teamId, userId)));
                }
            }
        }
    }

    private void handleRemoveMembers(Long teamId, ScimPatchOp.PatchOperation op) {
        String path = op.path() == null ? "" : op.path();
        if (path.startsWith("members[value eq ")) {
            String val = path.replace("members[value eq ", "").replace("]", "").replaceAll("^\"|\"$", "");
            resolveUserId(val).ifPresent(userId ->
                    members.deleteById(new TeamMemberEntity.Id(teamId, userId)));
        } else if ("members".equalsIgnoreCase(path)) {
            members.deleteByTeamId(teamId);
        }
    }

    private Optional<Long> resolveUserId(String value) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            return Optional.of(Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            return users.findByUsername(value.trim().toLowerCase(Locale.ROOT)).map(UserEntity::getId);
        }
    }

    private ScimGroupDto toDto(TeamEntity team, List<TeamMemberEntity> teamMembers, Map<Long, UserEntity> userMap) {
        List<ScimGroupDto.Member> memberDtos = new ArrayList<>();
        if (teamMembers != null) {
            for (TeamMemberEntity tm : teamMembers) {
                UserEntity u = userMap.get(tm.getId().userId());
                String display = u != null ? u.getUsername() : String.valueOf(tm.getId().userId());
                memberDtos.add(new ScimGroupDto.Member(
                        String.valueOf(tm.getId().userId()),
                        display,
                        "/scim/v2/Users/" + tm.getId().userId()));
            }
        }

        ScimGroupDto.Meta meta = new ScimGroupDto.Meta(
                "Group",
                team.getCreatedAt() != null ? team.getCreatedAt().toString() : null,
                null,
                "/scim/v2/Groups/" + team.getId());

        return new ScimGroupDto(
                List.of(ScimGroupDto.SCHEMA_GROUP),
                String.valueOf(team.getId()),
                null,
                team.getName(),
                memberDtos,
                meta);
    }
}

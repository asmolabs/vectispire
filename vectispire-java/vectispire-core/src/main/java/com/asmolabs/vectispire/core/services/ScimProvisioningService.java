package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * What an identity provider may do to accounts and teams through SCIM (RFC 7644).
 *
 * <p><b>Deactivating an account revokes its sessions in the same call.</b> That is the point of
 * provisioning from a directory: somebody who leaves is out when the directory says so, not when
 * their session happens to expire.
 *
 * <p><b>Group writes are transactional and account writes are not</b>, as they were when this
 * lived in the controllers: a group's rewrite deletes its memberships and inserts the new ones,
 * and a failure halfway would leave a team with half its members. The audit entry is written
 * inside that boundary; it opens its own transaction, so it survives a rollback.
 *
 * <p><b>SCIM marks its membership rows, and that is what keeps two directories from fighting.</b>
 * The OIDC claim's reconciliation removes only the memberships it set itself; without this mark,
 * its own would be indistinguishable and the first sign-in would carry away what provisioning had
 * just written.
 */
@Service
public class ScimProvisioningService {

    private final Users users;
    private final Teams teams;
    private final TeamMembers members;
    private final AuthService auth;
    private final AuditLogService audit;
    private final Clock clock;

    public ScimProvisioningService(
            Users users, Teams teams, TeamMembers members, AuthService auth, AuditLogService audit, Clock clock) {
        this.users = users;
        this.teams = teams;
        this.members = members;
        this.auth = auth;
        this.audit = audit;
        this.clock = clock;
    }

    /** An account as the directory describes it, already read out of the SCIM document. */
    public record UserAttributes(
            String userName, String displayName, String email, String externalId, Boolean active, String role) {}

    public record PatchOperation(String op, String path, JsonNode value) {}

    public sealed interface UserCreation {
        record Created(UserEntity user) implements UserCreation {}

        record UsernameTaken() implements UserCreation {}
    }

    /** @param display the member's username, or its identifier when the account is gone */
    public record GroupMember(long userId, String display) {}

    public record GroupView(TeamEntity team, List<GroupMember> members) {}

    public sealed interface GroupCreation {
        record Created(GroupView group) implements GroupCreation {}

        record NameTaken() implements GroupCreation {}
    }

    // --- Users ---------------------------------------------------------------------------------

    public List<UserEntity> users(String filter) {
        if (filter != null && !filter.isBlank()) {
            return filterUsers(filter.trim());
        }
        return users.findAllByOrderByUsernameAsc();
    }

    public Optional<UserEntity> user(Long id) {
        return users.findById(id);
    }

    public UserCreation createUser(UserAttributes attributes, RequestActor origin) {
        String username = attributes.userName() == null ? "" : attributes.userName().trim().toLowerCase(Locale.ROOT);
        AccountRules.validateUsername(username).ifPresent(msg -> {
            throw new IllegalArgumentException(msg);
        });

        if (users.findByUsername(username).isPresent()) {
            return new UserCreation.UsernameTaken();
        }

        Instant now = clock.instant();
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setDisplayName(attributes.displayName());
        user.setEmail(attributes.email());
        user.setKeycloakId(attributes.externalId());
        user.setIsActive(attributes.active() == null || attributes.active());
        user.setRole(roleOf(attributes.role()));
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
                origin.ipAddress(),
                origin.userAgent()));

        return new UserCreation.Created(saved);
    }

    /** Empty when there is no such account. */
    public Optional<UserEntity> replaceUser(Long id, UserAttributes attributes, RequestActor origin) {
        Optional<UserEntity> found = users.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }

        UserEntity user = found.get();
        boolean wasActive = Boolean.TRUE.equals(user.getIsActive());
        boolean nowActive = attributes.active() == null || attributes.active();

        user.setDisplayName(attributes.displayName());
        user.setEmail(attributes.email());
        if (attributes.externalId() != null) {
            user.setKeycloakId(attributes.externalId());
        }
        user.setIsActive(nowActive);
        user.setRole(roleOf(attributes.role()));
        user.setUpdatedAt(clock.instant());

        UserEntity saved = users.save(user);

        if (wasActive && !nowActive) {
            auth.revokeAllForUser(saved.getId());
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    "SCIM",
                    "SCIM deactivated account and revoked all active sessions for " + saved.getUsername(),
                    saved.getUsername(),
                    origin.ipAddress(),
                    origin.userAgent()));
        } else {
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    "SCIM",
                    "SCIM updated account: " + saved.getUsername(),
                    saved.getUsername(),
                    origin.ipAddress(),
                    origin.userAgent()));
        }

        return Optional.of(saved);
    }

    /** Empty when there is no such account. */
    public Optional<UserEntity> patchUser(Long id, List<PatchOperation> operations, RequestActor origin) {
        Optional<UserEntity> found = users.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }

        UserEntity user = found.get();
        boolean wasActive = Boolean.TRUE.equals(user.getIsActive());

        if (operations != null) {
            for (PatchOperation op : operations) {
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
                    origin.ipAddress(),
                    origin.userAgent()));
        }

        return Optional.of(saved);
    }

    /** Idempotent, as RFC 7644 lets it be: deleting an account that is not there is not an error. */
    public void deleteUser(Long id, RequestActor origin) {
        users.findById(id).ifPresent(user -> {
            auth.revokeAllForUser(user.getId());
            users.delete(user);
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_DELETED,
                    "SCIM",
                    "SCIM deleted account: " + user.getUsername(),
                    user.getUsername(),
                    origin.ipAddress(),
                    origin.userAgent()));
        });
    }

    private void applyPatch(UserEntity user, PatchOperation op) {
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

    /** A role the directory names and this system does not know falls back to the least one. */
    private static String roleOf(String requested) {
        if (requested != null && Role.of(requested.toUpperCase(Locale.ROOT)).isPresent()) {
            return requested.toUpperCase(Locale.ROOT);
        }
        return Role.USER.name();
    }

    // --- Groups --------------------------------------------------------------------------------

    public List<GroupView> groups() {
        List<TeamEntity> allTeams = teams.findAll();
        Map<Long, UserEntity> userMap = userMap();
        return allTeams.stream()
                .map(t -> viewOf(t, members.findByTeamId(t.getId()), userMap))
                .toList();
    }

    public Optional<GroupView> group(Long id) {
        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        Map<Long, UserEntity> userMap = userMap();
        return Optional.of(viewOf(found.get(), members.findByTeamId(id), userMap));
    }

    /** @param memberValues each member's SCIM {@code value}: an account id, or a username */
    @Transactional
    public GroupCreation createGroup(String displayName, List<String> memberValues, RequestActor origin) {
        String name = displayName == null ? "" : displayName.trim();
        if (name.isBlank()) {
            throw new IllegalArgumentException("Group displayName cannot be blank.");
        }

        if (teams.findByNameIgnoreCase(name).isPresent()) {
            return new GroupCreation.NameTaken();
        }

        Instant now = clock.instant();
        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setDescription("Created via SCIM");
        team.setCreatedAt(now);
        TeamEntity saved = teams.save(team);

        if (memberValues != null) {
            for (String value : memberValues) {
                resolveUserId(value).ifPresent(userId ->
                        members.save(new TeamMemberEntity(saved.getId(), userId, TeamMemberEntity.Origin.SCIM)));
            }
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED,
                "SCIM",
                "SCIM created team: " + name,
                name,
                origin.ipAddress(),
                origin.userAgent()));

        Map<Long, UserEntity> userMap = userMap();
        return new GroupCreation.Created(viewOf(saved, members.findByTeamId(saved.getId()), userMap));
    }

    /** Replaces the name, when one is given, and the whole membership. Empty when there is no such team. */
    @Transactional
    public Optional<GroupView> replaceGroup(Long id, String displayName, List<String> memberValues, RequestActor origin) {
        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }

        TeamEntity team = found.get();
        if (displayName != null && !displayName.isBlank()) {
            team.setName(displayName.trim());
            teams.save(team);
        }

        members.deleteByTeamId(id);
        if (memberValues != null) {
            for (String value : memberValues) {
                resolveUserId(value).ifPresent(userId ->
                        members.save(new TeamMemberEntity(id, userId, TeamMemberEntity.Origin.SCIM)));
            }
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED,
                "SCIM",
                "SCIM updated team: " + team.getName(),
                team.getName(),
                origin.ipAddress(),
                origin.userAgent()));

        Map<Long, UserEntity> userMap = userMap();
        return Optional.of(viewOf(team, members.findByTeamId(id), userMap));
    }

    /** Empty when there is no such team. */
    @Transactional
    public Optional<GroupView> patchGroup(Long id, List<PatchOperation> operations, RequestActor origin) {
        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }

        TeamEntity team = found.get();
        if (operations != null) {
            for (PatchOperation op : operations) {
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
                origin.ipAddress(),
                origin.userAgent()));

        Map<Long, UserEntity> userMap = userMap();
        return Optional.of(viewOf(team, members.findByTeamId(id), userMap));
    }

    @Transactional
    public void deleteGroup(Long id, RequestActor origin) {
        teams.findById(id).ifPresent(team -> {
            members.deleteByTeamId(id);
            teams.delete(team);
            audit.record(new AuditLogService.Record(
                    AuditOperation.TEAM_UPDATED,
                    "SCIM",
                    "SCIM deleted team: " + team.getName(),
                    team.getName(),
                    origin.ipAddress(),
                    origin.userAgent()));
        });
    }

    private void handleAddMembers(Long teamId, JsonNode value) {
        if (value == null) return;
        if (value.isArray()) {
            for (JsonNode item : value) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asText()).ifPresent(userId ->
                            members.save(new TeamMemberEntity(teamId, userId, TeamMemberEntity.Origin.SCIM)));
                }
            }
        } else if (value.isObject() && value.has("members") && value.get("members").isArray()) {
            for (JsonNode item : value.get("members")) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asText()).ifPresent(userId ->
                            members.save(new TeamMemberEntity(teamId, userId, TeamMemberEntity.Origin.SCIM)));
                }
            }
        }
    }

    private void handleRemoveMembers(Long teamId, PatchOperation op) {
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

    private Map<Long, UserEntity> userMap() {
        return users.findAll().stream().collect(Collectors.toMap(UserEntity::getId, u -> u));
    }

    private static GroupView viewOf(TeamEntity team, List<TeamMemberEntity> teamMembers, Map<Long, UserEntity> userMap) {
        List<GroupMember> memberViews = new ArrayList<>();
        if (teamMembers != null) {
            for (TeamMemberEntity tm : teamMembers) {
                UserEntity u = userMap.get(tm.getId().userId());
                String display = u != null ? u.getUsername() : String.valueOf(tm.getId().userId());
                memberViews.add(new GroupMember(tm.getId().userId(), display));
            }
        }
        return new GroupView(team, memberViews);
    }
}

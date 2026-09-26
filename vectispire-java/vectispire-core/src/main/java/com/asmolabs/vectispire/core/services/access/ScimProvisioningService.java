package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.TeamMembers;
import com.asmolabs.vectispire.core.repositories.Teams;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
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
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;

/**
 * What an identity provider may do to accounts and teams through SCIM (RFC 7644).
 *
 * <p><b>Deactivating an account revokes its sessions in the same call.</b> That is the point of
 * provisioning from a directory: somebody who leaves is out when the directory says so, not when
 * their session happens to expire.
 *
 * <p><b>Group writes are transactional and account writes are not</b>, as they were when this
 * lived in the controllers: a group's rewrite deletes its memberships and inserts the new ones,
 * and a failure halfway would leave a team with half its members.
 *
 * <p><b>The group's audit entry is written after that transaction commits, never inside it.</b>
 * The entry opens its own {@code REQUIRES_NEW} transaction, and on SQLite — where the lock is the
 * file — that second connection waited on the first one's write lock: every group write answered
 * {@code SQLITE_BUSY}, whichever class held the boundary. The boundary is therefore a {@link
 * TransactionTemplate}, as in {@code AgentAdministrationService}, since an annotated method cannot
 * put the entry after its own commit. What commits together is unchanged — the team and its
 * memberships; the cost is that a write which rolls back is no longer recorded as attempted.
 *
 * <p><b>What the directory may not do, and why each limit is here.</b> The SCIM bearer token sits
 * in the identity provider's configuration, outside this deployment's control; it was treated as an
 * unrestricted administrator. With it, one {@code PUT} rebound the bootstrap governor to an
 * attacker's IdP subject — the next OIDC sign-in landed on that account, with no password and no
 * local MFA — or granted SUPERUSER to an account the attacker controlled; a {@code PUT} without
 * {@code roles}, which many IdPs send, silently demoted anyone to USER; the last administrator could
 * be deactivated or deleted; and a role change left the old sessions open. So:
 * <ul>
 *   <li>administrative accounts (ADMIN, SUPERUSER) are not the directory's to change: replacing,
 *       patching or deleting one is refused, and they are administered in Vectispire;
 *   <li>the directory grants only non-administrative roles;
 *   <li>an absent role leaves the account's role as it is;
 *   <li>{@code externalId} is set once and never rebound;
 *   <li>a role change closes the account's sessions, as a deactivation does.
 * </ul>
 *
 * <p><b>SCIM marks its membership rows, and that is what keeps two directories from fighting.</b>
 * The OIDC claim's reconciliation removes only the memberships it set itself; without this mark,
 * its own would be indistinguishable and the first sign-in would carry away what provisioning had
 * just written.
 */
@Service
public class ScimProvisioningService {

    /** The width of {@code display_name}, {@code email} and {@code keycloak_id}. */
    private static final int IDENTITY_COLUMN = 255;

    private final Users users;
    private final Teams teams;
    private final TeamMembers members;
    private final AuthService auth;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public ScimProvisioningService(
            Users users,
            Teams teams,
            TeamMembers members,
            AuthService auth,
            AuditLogService audit,
            TransactionTemplate transactions,
            Clock clock) {
        this.users = users;
        this.teams = teams;
        this.members = members;
        this.auth = auth;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** An account as the directory describes it, already read out of the SCIM document. */
    public record UserAttributes(
            String userName, String displayName, String email, String externalId, Boolean active, String role) {}

    /**
     * One operation of a PATCH, its value left as the tree the request carried.
     *
     * @param value a Jackson <b>3</b> node, unlike the Jackson 2 the rest of this codebase is
     *     written against ({@code CoreConfiguration} says why). The HTTP layer is Spring Boot 4's
     *     Jackson 3, and it cannot build a Jackson 2 {@code JsonNode}: with one here, every SCIM
     *     PATCH that reached the route failed to deserialize and answered 500 — deactivating an
     *     account from the directory included. The unit test built the node by hand and never
     *     crossed that layer.
     */
    public record PatchOperation(String op, String path, JsonNode value) {}

    /** An administrative account: not the directory's to change. Answered 403. */
    public static final class ProtectedAccountException extends RuntimeException {
        ProtectedAccountException(String username) {
            super("The account \"" + username + "\" holds an administrative role and is administered in "
                    + "Vectispire, not through SCIM.");
        }
    }

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
        user.setDisplayName(bounded(attributes.displayName(), "displayName"));
        user.setEmail(bounded(attributes.email(), "emails"));
        user.setKeycloakId(bounded(attributes.externalId(), "externalId"));
        user.setIsActive(attributes.active() == null || attributes.active());
        user.setRole(grantable(attributes.role(), Role.USER.name()));
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

        UserEntity user = requireProvisionable(found.get());
        boolean wasActive = Boolean.TRUE.equals(user.getIsActive());
        boolean nowActive = attributes.active() == null || attributes.active();
        String previousRole = user.getRole();
        String role = grantable(attributes.role(), previousRole);

        user.setDisplayName(bounded(attributes.displayName(), "displayName"));
        user.setEmail(bounded(attributes.email(), "emails"));
        if (attributes.externalId() != null) {
            bindOnce(user, bounded(attributes.externalId(), "externalId"));
        }
        user.setIsActive(nowActive);
        user.setRole(role);
        user.setUpdatedAt(clock.instant());

        UserEntity saved = users.save(user);

        if (!role.equals(previousRole) && nowActive) {
            // A role change from the directory closes the sessions, as it does from the admin
            // screen: an open session would otherwise keep what the directory just took away.
            auth.revokeAllForUser(saved.getId());
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    "SCIM",
                    "SCIM changed the role of " + saved.getUsername() + " from " + previousRole + " to " + role
                            + " and revoked its sessions",
                    saved.getUsername(),
                    origin.ipAddress(),
                    origin.userAgent()));
        } else if (wasActive && !nowActive) {
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

        UserEntity user = requireProvisionable(found.get());
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
        users.findById(id).map(this::requireProvisionable).ifPresent(user -> {
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
            if (value.has("displayName") && value.get("displayName").isString()) {
                user.setDisplayName(bounded(value.get("displayName").asString(), "displayName"));
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

    /**
     * The role the directory asked for, if it may grant it.
     *
     * @param unchanged what to keep when the document names no role, or one this version does not
     *     know: the account's own role on a replacement, USER on a creation. It used to be USER in
     *     both cases, so a replacement without {@code roles} demoted whoever it named.
     * @throws IllegalArgumentException for an administrative role, which is granted in Vectispire
     */
    private static String grantable(String requested, String unchanged) {
        Optional<Role> role = requested == null ? Optional.empty() : Role.of(requested.trim().toUpperCase(Locale.ROOT));
        if (role.isEmpty()) {
            return unchanged;
        }
        if (role.get().isAdministrative()) {
            throw new IllegalArgumentException("SCIM cannot grant the " + role.get().name()
                    + " role: administrative roles are granted in Vectispire.");
        }
        return role.get().name();
    }

    /** Refuses an administrative account: see the class note. */
    private UserEntity requireProvisionable(UserEntity user) {
        if (Role.of(user.getRole()).map(Role::isAdministrative).orElse(false)) {
            throw new ProtectedAccountException(user.getUsername());
        }
        return user;
    }

    /**
     * An attribute the provider sent, refused when its column cannot hold it.
     *
     * <p>Refused rather than cut: a truncated address is somebody else's address, and a truncated
     * external id binds the account to a subject that does not exist. The refusal is a SCIM 400
     * the provider logs against the user it was provisioning, where it used to be a 500 from the
     * insert.
     */
    private static String bounded(String value, String attribute) {
        return BoundedText.within(value, IDENTITY_COLUMN, "The SCIM attribute " + attribute);
    }

    /**
     * Sets the identity-provider subject once.
     *
     * <p>Rebinding it is how an account is taken over: the next OIDC sign-in with the new subject
     * lands on it. A directory that renames its own identifiers re-creates the account instead.
     */
    private static void bindOnce(UserEntity user, String externalId) {
        if (user.getKeycloakId() != null && !user.getKeycloakId().equals(externalId)) {
            throw new IllegalArgumentException("externalId is immutable once set: this account is already "
                    + "bound to another identity-provider subject.");
        }
        user.setKeycloakId(externalId);
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
    public GroupCreation createGroup(String displayName, List<String> memberValues, RequestActor origin) {
        String name = displayName == null ? "" : displayName.trim();
        if (name.isBlank()) {
            throw new IllegalArgumentException("Group displayName cannot be blank.");
        }

        GroupCreation outcome = transactions.execute(status -> {
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

            Map<Long, UserEntity> userMap = userMap();
            return new GroupCreation.Created(viewOf(saved, members.findByTeamId(saved.getId()), userMap));
        });

        if (outcome instanceof GroupCreation.Created) {
            recordGroup(origin, "SCIM created team: " + name, name);
        }
        return outcome;
    }

    /** Replaces the name, when one is given, and the whole membership. Empty when there is no such team. */
    public Optional<GroupView> replaceGroup(Long id, String displayName, List<String> memberValues, RequestActor origin) {
        Optional<GroupView> replaced = transactions.execute(status -> {
            Optional<TeamEntity> found = teams.findById(id);
            if (found.isEmpty()) {
                return Optional.<GroupView>empty();
            }

            TeamEntity team = found.get();
            if (displayName != null && !displayName.isBlank()) {
                team.setName(displayName.trim());
                // Flushed now, not at commit: `deleteByTeamId` below clears the persistence
                // context, and a rename still pending in it was discarded — the response carried
                // the new name, the row kept the old one, and nothing failed.
                teams.saveAndFlush(team);
            }

            members.deleteByTeamId(id);
            if (memberValues != null) {
                for (String value : memberValues) {
                    resolveUserId(value).ifPresent(userId ->
                            members.save(new TeamMemberEntity(id, userId, TeamMemberEntity.Origin.SCIM)));
                }
            }

            Map<Long, UserEntity> userMap = userMap();
            return Optional.of(viewOf(team, members.findByTeamId(id), userMap));
        });

        replaced.ifPresent(group ->
                recordGroup(origin, "SCIM updated team: " + group.team().getName(), group.team().getName()));
        return replaced;
    }

    /** Empty when there is no such team. */
    public Optional<GroupView> patchGroup(Long id, List<PatchOperation> operations, RequestActor origin) {
        Optional<GroupView> patched = transactions.execute(status -> {
            Optional<TeamEntity> found = teams.findById(id);
            if (found.isEmpty()) {
                return Optional.<GroupView>empty();
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

            Map<Long, UserEntity> userMap = userMap();
            return Optional.of(viewOf(team, members.findByTeamId(id), userMap));
        });

        patched.ifPresent(group ->
                recordGroup(origin, "SCIM patched team: " + group.team().getName(), group.team().getName()));
        return patched;
    }

    /** Idempotent, as RFC 7644 lets it be: deleting a group that is not there is not an error. */
    public void deleteGroup(Long id, RequestActor origin) {
        Optional<TeamEntity> deleted = transactions.execute(status -> teams.findById(id).map(team -> {
            members.deleteByTeamId(id);
            teams.delete(team);
            return team;
        }));

        deleted.ifPresent(team -> recordGroup(origin, "SCIM deleted team: " + team.getName(), team.getName()));
    }

    /**
     * Called only once the group's transaction has committed — see the class note for the
     * deadlock this avoids. Attributed to the team's name, as these entries always were.
     */
    private void recordGroup(RequestActor origin, String description, String teamName) {
        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED, "SCIM", description, teamName, origin.ipAddress(), origin.userAgent()));
    }

    private void handleAddMembers(Long teamId, JsonNode value) {
        if (value == null) return;
        if (value.isArray()) {
            for (JsonNode item : value) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asString()).ifPresent(userId ->
                            members.save(new TeamMemberEntity(teamId, userId, TeamMemberEntity.Origin.SCIM)));
                }
            }
        } else if (value.isObject() && value.has("members") && value.get("members").isArray()) {
            for (JsonNode item : value.get("members")) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asString()).ifPresent(userId ->
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

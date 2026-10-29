package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamMembership;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
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
 * The entry opens its own {@code REQUIRES_NEW} transaction: inside the group's it would record a
 * rewrite that may still roll back, on a second pooled connection held while the first keeps its
 * locks. (On the SQLite fixture of the time that second connection waited on the first one's
 * lock on the file, and every group write answered {@code SQLITE_BUSY}.) The boundary is
 * therefore a {@link TransactionTemplate}, as in {@code AgentAdministrationService}, since an
 * annotated method cannot
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
 *   <li>the directory grants only the roles scoped to what they are given — USER and
 *       SECURITY_CHAMPION — see {@link #grantable};
 *   <li>an absent role leaves the account's role as it is;
 *   <li>{@code externalId} is set once and never rebound, and an existing account that holds a
 *       privileged role or a local second factor is not bound at all — see {@link #bindOnce} — nor one
 *       the directory lowered out of a privileged role, until an administrator sets its role;
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

    /**
     * Who acted, in the audit trail: the identity provider through its token. The entries used to
     * carry the account they changed as their actor, so a provisioning read as the account acting
     * on itself. A space keeps it apart from every account name (AccountRules' grammar has none).
     */
    public static final String ACTOR = "SCIM provisioning";

    /** The width of {@code display_name}, {@code email} and {@code keycloak_id}. */
    private static final int IDENTITY_COLUMN = 255;

    private final UserRepository users;
    private final TeamRepository teams;
    private final TeamMemberRepository members;
    private final AuthService auth;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final boolean linkPrivileged;

    public ScimProvisioningService(
            UserRepository users,
            TeamRepository teams,
            TeamMemberRepository members,
            AuthService auth,
            AuditLogService audit,
            TransactionTemplate transactions,
            Clock clock,
            @Value("${vectispire.oidc.link-privileged-accounts:false}") boolean linkPrivileged) {
        this.users = users;
        this.teams = teams;
        this.members = members;
        this.auth = auth;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
        this.linkPrivileged = linkPrivileged;
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

    /**
     * A filter this endpoint does not evaluate: 400 with {@code scimType} {@code invalidFilter} (RFC 7644
     * §3.4.2.2, §3.12), never the whole list.
     */
    public static final class InvalidFilterException extends InvalidInputException {
        InvalidFilterException(String filter) {
            super("Unsupported filter \"" + BoundedText.clip(filter, 200) + "\": only userName eq \"…\" and "
                    + "externalId eq \"…\" are evaluated.");
        }
    }

    public sealed interface UserCreation {
        record Created(UserView user) implements UserCreation {}

        record UsernameTaken() implements UserCreation {}

        /** Another account is bound to this {@code externalId}: nothing written. */
        record ExternalIdTaken() implements UserCreation {}
    }

    /** A replacement's outcome. {@code ExternalIdTaken} is a binding to a subject another account holds. */
    public sealed interface UserChange {
        record Changed(UserView user) implements UserChange {}

        record Absent() implements UserChange {}

        record ExternalIdTaken() implements UserChange {}
    }

    /** @param display the member's username, or its identifier when the account is gone */
    public record GroupMember(long userId, String display) {}

    /** A team as SCIM describes it: the row's properties under their own names, and its members. */
    public record GroupView(Long id, String name, Instant createdAt, List<GroupMember> members) {}

    public sealed interface GroupCreation {
        record Created(GroupView group) implements GroupCreation {}

        record NameTaken() implements GroupCreation {}
    }

    /**
     * A replacement's or a patch's outcome. {@code NameTaken} is a rename to a name another team holds,
     * refused with nothing written — the membership rewrite beside it included.
     */
    public sealed interface GroupChange {
        record Changed(GroupView group) implements GroupChange {}

        record Absent() implements GroupChange {}

        record NameTaken() implements GroupChange {}
    }

    // --- Paging --------------------------------------------------------------------------------

    /**
     * One page of a SCIM list, as RFC 7644 §3.4.2.4 pages it: {@code startIndex} 1-based, {@code count} the
     * most resources answered, {@code totalResults} every resource the request matched.
     *
     * <p><b>SCIM's rule, not {@code ListWindow}'s.</b> The RFC does not let a provider refuse these two: a
     * {@code startIndex} below 1 "SHALL be interpreted as 1", a negative {@code count} as 0, and a count of 0
     * answers the total alone. An identity provider sends them as it was built to, and one answered a 400
     * stops synchronising. A {@code count} past {@link #MAX_COUNT} is answered with {@link #MAX_COUNT} — the
     * RFC lets a provider return fewer — and the client, reading {@code itemsPerPage} and {@code
     * totalResults}, asks for the next.
     *
     * <p><b>Asked neither, every resource</b>, as before the routes read them: {@code /Users} declared both
     * and ignored them, {@code /Groups} declared neither, and either answering fewer now would move what a
     * client written against 0.11.0 reads. A {@code startIndex} alone answers every resource from there.
     *
     * @param startIndex the 1-based index of the first resource, as interpreted
     * @param totalResults every resource the request matched, whatever the page
     */
    public record Page<T>(List<T> resources, int totalResults, int startIndex) {

        /** The most resources a page answers: the figure every list route pages by. */
        public static final int MAX_COUNT = ListWindow.MAX_LIMIT;

        /** @param all every resource the request matched, in the order the pages are cut from */
        public static <T> Page<T> of(List<T> all, Integer startIndex, Integer count) {
            int start = startIndex == null ? 1 : Math.max(1, startIndex);
            int from = (int) Math.min(start - 1L, all.size());
            int size = count == null ? all.size() : Math.clamp(count, 0, MAX_COUNT);
            int to = (int) Math.min((long) from + size, all.size());
            return new Page<>(List.copyOf(all.subList(from, to)), all.size(), start);
        }

        public <R> Page<R> map(Function<T, R> mapper) {
            return new Page<>(resources.stream().map(mapper).toList(), totalResults, startIndex);
        }
    }

    // --- Users ---------------------------------------------------------------------------------

    private List<UserView> users(String filter) {
        List<UserEntity> found = filter != null && !filter.isBlank()
                ? filterUsers(filter.trim())
                : users.findAllByOrderByUsernameAsc();
        return found.stream().map(UserView::of).toList();
    }

    /**
     * The accounts the filter matches — every one without a filter — by username, all of them or the page
     * {@code startIndex} and {@code count} name ({@link Page}). A username is unique, so the order is one a
     * page can be cut from.
     *
     * @throws InvalidInputException a filter SCIM here does not support
     */
    public Page<UserView> users(String filter, Integer startIndex, Integer count) {
        return Page.of(users(filter), startIndex, count);
    }

    public Optional<UserView> user(Long id) {
        return users.findById(id).map(UserView::of);
    }

    public UserCreation createUser(UserAttributes attributes, RequestActor origin) {
        String username = attributes.userName() == null ? "" : attributes.userName().trim().toLowerCase(Locale.ROOT);
        AccountRules.validateUsername(username).ifPresent(msg -> {
            throw new InvalidInputException(msg);
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
        // Asked before the insert: the column's unique constraint answered it, and the directory read a
        // 500 it could not act on where "already provisioned, link it" is what it needed to hear.
        if (boundToAnother(user.getKeycloakId(), null)) {
            return new UserCreation.ExternalIdTaken();
        }
        // A password nobody knows, so the account has none to sign in with; it signs in through the
        // provider. Not "must change": that flag held every federated session of a provisioned
        // account on the change-password screen, which asks for a current password nobody had.
        user.setPassword(PasswordHasher.hash(UUID.randomUUID().toString()));
        user.setMustChangePassword(false);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);

        UserEntity saved = users.save(user);

        audit.record(new AuditLogService.Record(
                AuditOperation.USER_CREATED,
                String.valueOf(saved.getId()),
                "SCIM provisioned account: " + username,
                ACTOR,
                origin.ipAddress(),
                origin.userAgent()));

        return new UserCreation.Created(UserView.of(saved));
    }

    public UserChange replaceUser(Long id, UserAttributes attributes, RequestActor origin) {
        Optional<UserEntity> found = users.findById(id);
        if (found.isEmpty()) {
            return new UserChange.Absent();
        }

        UserEntity user = requireProvisionable(found.get());
        boolean wasActive = Boolean.TRUE.equals(user.getIsActive());
        boolean nowActive = attributes.active() == null || attributes.active();
        String previousRole = user.getRole();
        String role = grantable(attributes.role(), previousRole);

        user.setDisplayName(bounded(attributes.displayName(), "displayName"));
        user.setEmail(bounded(attributes.email(), "emails"));
        if (attributes.externalId() != null) {
            String externalId = bounded(attributes.externalId(), "externalId");
            if (user.getKeycloakId() == null && boundToAnother(externalId, id)) {
                return new UserChange.ExternalIdTaken();
            }
            bindOnce(user, externalId, linkPrivileged);
        }
        if (user.getKeycloakId() == null && user.getScimLoweredFrom() == null && heldPrivilege(previousRole)
                && !heldPrivilege(role)) {
            // Lowering stays the directory's to do — taking a privilege away must not wait for anybody —
            // but the account keeps what it held for the binding: see bindOnce.
            user.setScimLoweredFrom(previousRole);
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
                    String.valueOf(saved.getId()),
                    "SCIM changed the role of " + saved.getUsername() + " from " + previousRole + " to " + role
                            + " and revoked its sessions",
                    ACTOR,
                    origin.ipAddress(),
                    origin.userAgent()));
        } else if (wasActive && !nowActive) {
            auth.revokeAllForUser(saved.getId());
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    String.valueOf(saved.getId()),
                    "SCIM deactivated account and revoked all active sessions for " + saved.getUsername(),
                    ACTOR,
                    origin.ipAddress(),
                    origin.userAgent()));
        } else {
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_UPDATED,
                    String.valueOf(saved.getId()),
                    "SCIM updated account: " + saved.getUsername(),
                    ACTOR,
                    origin.ipAddress(),
                    origin.userAgent()));
        }

        return new UserChange.Changed(UserView.of(saved));
    }

    /** Empty when there is no such account. */
    public Optional<UserView> patchUser(Long id, List<PatchOperation> operations, RequestActor origin) {
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
                    String.valueOf(saved.getId()),
                    "SCIM deactivated account and revoked active sessions for " + saved.getUsername(),
                    ACTOR,
                    origin.ipAddress(),
                    origin.userAgent()));
        }

        return Optional.of(UserView.of(saved));
    }

    /** Idempotent, as RFC 7644 lets it be: deleting an account that is not there is not an error. */
    public void deleteUser(Long id, RequestActor origin) {
        users.findById(id).map(this::requireProvisionable).ifPresent(user -> {
            auth.revokeAllForUser(user.getId());
            users.delete(user);
            audit.record(new AuditLogService.Record(
                    AuditOperation.USER_DELETED,
                    String.valueOf(user.getId()),
                    "SCIM deleted account: " + user.getUsername(),
                    ACTOR,
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

    /**
     * The two filters this endpoint answers: {@code userName eq "…"} and {@code externalId eq "…"}, the
     * attribute and the operator in any case (RFC 7644 §3.4.2.2), the value a JSON string.
     *
     * <p><b>Anything else is refused, never answered with every account.</b> An unsupported filter fell
     * back to the whole list: a directory asking {@code emails[value eq "a@example.org"]} or {@code userName
     * eq "a" and active eq true} before creating an account read the first account of the list as the
     * match, and could bind or overwrite the wrong one. RFC 7644 answers such a filter 400 {@code
     * invalidFilter}, which tells the directory to look another way.
     */
    private List<UserEntity> filterUsers(String filter) {
        java.util.regex.Matcher matched = SUPPORTED_FILTER.matcher(filter);
        if (!matched.matches()) {
            throw new InvalidFilterException(filter);
        }
        String value = matched.group(2).replaceAll("\\\\(.)", "$1");
        return "username".equalsIgnoreCase(matched.group(1))
                ? users.findByUsername(value.toLowerCase(Locale.ROOT)).map(List::of).orElse(List.of())
                : users.findByKeycloakId(value).map(List::of).orElse(List.of());
    }

    /** {@code userName} or {@code externalId}, {@code eq}, and a quoted string whose escapes are a backslash and one character. */
    private static final java.util.regex.Pattern SUPPORTED_FILTER = java.util.regex.Pattern.compile(
            "(?i)(userName|externalId)\\s+eq\\s+\"((?:[^\"\\\\]|\\\\.)*)\"");

    /**
     * The role the directory asked for, if it may grant it.
     *
     * @param unchanged what to keep when the document names no role, or one this version does not
     *     know: the account's own role on a replacement, USER on a creation. It used to be USER in
     *     both cases, so a replacement without {@code roles} demoted whoever it named.
     * <p><b>Not a role that sees the whole estate.</b> Only the administrative roles used to be
     * refused, so the token held in the identity provider — a third system, with its own operators
     * — could make any account a CISO, who rewrites the gate policy and approves triage, or an
     * auditor, who reads every account's actions and every target's posture. A role with a global
     * security scope is granted in Vectispire, like an administrative one, and by the same people.
     * Deliberately not widened by a setting: an organisation that wants its directory to decide
     * those roles is asking the directory's token to hold the estate. Naming the role an account
     * already holds is not a grant, so a directory that sends it back on every replacement is not
     * refused.
     *
     * @throws InvalidInputException for a role with a global security scope, which is granted in
     *     Vectispire
     */
    private static String grantable(String requested, String unchanged) {
        Optional<Role> role = requested == null ? Optional.empty() : Role.of(requested.trim().toUpperCase(Locale.ROOT));
        if (role.isEmpty() || role.get().name().equals(unchanged)) {
            return unchanged;
        }
        if (role.get().isAdministrative() || role.get().hasGlobalSecurityScope()) {
            throw new InvalidInputException("SCIM cannot grant the " + role.get().name()
                    + " role: roles that administer or see the whole estate are granted in Vectispire.");
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

    private boolean boundToAnother(String externalId, Long id) {
        return externalId != null
                && users.findByKeycloakId(externalId).filter(other -> !other.getId().equals(id)).isPresent();
    }

    private static boolean heldPrivilege(String role) {
        return Role.of(role).map(ExternalIdentityService::privileged).orElse(true);
    }

    /**
     * Sets the identity-provider subject once.
     *
     * <p>Rebinding it is how an account is taken over: the next OIDC sign-in with the new subject
     * lands on it. A directory that renames its own identifiers re-creates the account instead.
     *
     * <p><b>And a first binding is a takeover too, of an account that holds something.</b> The token
     * could not <em>grant</em> a CISO, an auditor or a champion ({@link #grantable}), but it could bind
     * an existing one, still unbound, to a subject of its choosing — and the next sign-in landed on
     * that account with neither its password nor its local second factor. The same rule as a claim's
     * ({@code ExternalIdentityService}): a privileged account is not bound from outside unless the
     * operator allows privileged linking, and one with a local second factor never is. Nothing in
     * Vectispire binds a subject to an existing account either, so the refusals say what does work:
     * a new account the directory provisions, given its role by an administrator, or the second
     * factor turned off by its owner. A binding the account already has is not a binding, and passes.
     *
     * <p><b>Nor an account the directory has just emptied.</b> The role is read at the binding, and
     * the directory may lower a role: a CISO lowered to User by one request was bound by the next.
     * {@code replaceUser} records the role it lowered an unbound account out of, and that record
     * refuses the binding until an administrator sets the account's role in Vectispire.
     */
    private static void bindOnce(UserEntity user, String externalId, boolean linkPrivileged) {
        if (user.getKeycloakId() != null && !user.getKeycloakId().equals(externalId)) {
            throw new InvalidInputException("externalId is immutable once set: this account is already "
                    + "bound to another identity-provider subject.");
        }
        if (user.getKeycloakId() == null) {
            boolean privileged = Role.of(user.getRole()).map(ExternalIdentityService::privileged).orElse(true);
            if (Boolean.TRUE.equals(user.getMfaEnabled())) {
                throw new InvalidInputException("This account has a local second factor, so the directory "
                        + "does not bind it to an identity-provider subject. Its owner turns the second factor off "
                        + "first, or the directory provisions a new account.");
            }
            if (privileged && !linkPrivileged) {
                throw new InvalidInputException("This account holds a privileged role, so the directory does "
                        + "not bind it to an identity-provider subject. Provision a new account and have an "
                        + "administrator grant it the role in Vectispire, or allow it with "
                        + "vectispire.oidc.link-privileged-accounts.");
            }
            if (user.getScimLoweredFrom() != null && !linkPrivileged) {
                throw new InvalidInputException("This account held the " + user.getScimLoweredFrom() + " role until "
                        + "the directory lowered it, so the directory does not bind it to an identity-provider "
                        + "subject until an administrator sets its role in Vectispire.");
            }
        }
        user.setKeycloakId(externalId);
    }

    // --- Groups --------------------------------------------------------------------------------

    /**
     * The teams by identifier, with their members, all of them or the page {@code startIndex} and {@code count}
     * name ({@link Page}): two statements whatever the number of teams — the memberships are read once, with
     * their usernames, and grouped here. The identifier was the table's order before, which is MySQL's and not
     * one PostgreSQL promises; a page needs one that is total.
     */
    public Page<GroupView> groups(Integer startIndex, Integer count) {
        List<TeamEntity> allTeams = teams.findAll().stream()
                .sorted(Comparator.comparing(TeamEntity::getId))
                .toList();
        Page<TeamEntity> page = Page.of(allTeams, startIndex, count);
        Map<Long, List<TeamMembership>> byTeam = page.resources().isEmpty()
                ? Map.of()
                : members.findAllMemberships().stream().collect(Collectors.groupingBy(TeamMembership::teamId));
        return page.map(t -> viewOf(t, byTeam.getOrDefault(t.getId(), List.of())));
    }

    public Optional<GroupView> group(Long id) {
        Optional<TeamEntity> found = teams.findById(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(viewOf(found.get(), members.findMembershipsOf(id)));
    }

    /** @param memberValues each member's SCIM {@code value}: an account id, or a username */
    public GroupCreation createGroup(String displayName, List<String> memberValues, RequestActor origin) {
        String name = groupName(displayName);

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

            return new GroupCreation.Created(viewOf(saved, members.findMembershipsOf(saved.getId())));
        });

        if (outcome instanceof GroupCreation.Created) {
            recordGroup(origin, "SCIM created team: " + name, name);
        }
        return outcome;
    }

    /**
     * Replaces the name, when one is given, and the whole membership.
     *
     * <p><b>A name another team holds is refused before anything is written</b>, as the creation
     * refuses it and compared the same way, whatever its case. The rename went on to the flush and the
     * unique constraint answered it 500 — on MySQL, whose collation folds case, while PostgreSQL's
     * does not and stored a second team the screens show under the same name.
     */
    public GroupChange replaceGroup(Long id, String displayName, List<String> memberValues, RequestActor origin) {
        // A blank name leaves the team's as it is: a replacement whose document omits it is not a rename.
        String name = displayName == null || displayName.isBlank() ? null : groupName(displayName);
        GroupChange outcome = transactions.execute(status -> {
            Optional<TeamEntity> found = teams.findById(id);
            if (found.isEmpty()) {
                return new GroupChange.Absent();
            }

            TeamEntity team = found.get();
            if (name != null) {
                if (takenByAnother(name, id)) {
                    return new GroupChange.NameTaken();
                }
                team.setName(name);
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

            return new GroupChange.Changed(viewOf(team, members.findMembershipsOf(id)));
        });

        if (outcome instanceof GroupChange.Changed(GroupView group)) {
            recordGroup(origin, "SCIM updated team: " + group.name(), group.name());
        }
        return outcome;
    }

    /**
     * Applies the operations in order, in one transaction: an operation refused rolls back those before it.
     *
     * <p><b>A rename is an operation too.</b> A directory renames a group by PATCH — {@code replace} with
     * the path {@code displayName}, or with no path and {@code displayName} in the value — and only the
     * members were read: the rename answered 200 with the old name and was recorded as a patch, so the
     * directory believed a name the team did not carry. A name another team holds is refused as the
     * replacement refuses it.
     *
     * <p><b>A {@code replace} of the members replaces them</b> (RFC 7644 §3.5.2.3): it was read as an
     * {@code add}, so a directory that synchronises a group by replacing its member list never removed
     * anybody — a person taken out of the group in the directory kept the team, and what it grants.
     */
    public GroupChange patchGroup(Long id, List<PatchOperation> operations, RequestActor origin) {
        GroupChange outcome = transactions.execute(status -> {
            Optional<TeamEntity> found = teams.findById(id);
            if (found.isEmpty()) {
                return new GroupChange.Absent();
            }

            TeamEntity team = found.get();
            if (operations != null) {
                for (PatchOperation op : operations) {
                    String opType = op.op() == null ? "" : op.op().toLowerCase(Locale.ROOT);
                    if ("add".equals(opType) || "replace".equals(opType)) {
                        Optional<String> rename = renameOf(op);
                        if (rename.isPresent()) {
                            if (takenByAnother(rename.get(), id)) {
                                status.setRollbackOnly();
                                return new GroupChange.NameTaken();
                            }
                            team.setName(rename.get());
                            // Flushed for the reason the replacement flushes: a removal of every
                            // member clears the persistence context, and a pending rename with it.
                            teams.saveAndFlush(team);
                        }
                        Optional<JsonNode> replacement = "replace".equals(opType) ? memberReplacementOf(op) : Optional.empty();
                        if (replacement.isPresent()) {
                            replaceMembers(id, replacement.get());
                        } else {
                            handleAddMembers(id, op.value());
                        }
                    } else if ("remove".equals(opType)) {
                        handleRemoveMembers(id, op);
                    }
                }
            }

            return new GroupChange.Changed(viewOf(team, members.findMembershipsOf(id)));
        });

        if (outcome instanceof GroupChange.Changed(GroupView group)) {
            recordGroup(origin, "SCIM patched team: " + group.name(), group.name());
        }
        return outcome;
    }

    /**
     * The member list a {@code replace} sets, if it sets one: the value of the path {@code members}, or
     * the {@code members} of a value without a path. Refused when it is not a list, rather than read as
     * nothing — an empty list is a statement (nobody), an unreadable one is not.
     */
    private static Optional<JsonNode> memberReplacementOf(PatchOperation op) {
        JsonNode value = op.value();
        JsonNode list;
        if (op.path() != null && !op.path().isBlank()) {
            if (!"members".equals(op.path().trim().toLowerCase(Locale.ROOT))) {
                return Optional.empty();
            }
            list = value;
        } else if (value != null && value.isObject() && value.has("members")) {
            list = value.get("members");
        } else {
            return Optional.empty();
        }
        if (list == null || !list.isArray()) {
            throw new InvalidInputException("Group members must be a list.");
        }
        return Optional.of(list);
    }

    /**
     * Makes the team's members exactly the accounts listed: the others' memberships are removed,
     * whatever set them — the replacement by PUT does the same — and the listed accounts not yet in
     * it join as SCIM's. A listed account already a member keeps its row, and the channel that set
     * it. An entry naming no account is skipped, as {@code add} skips it, so a list of unknown
     * accounts empties the team: what the directory said is that none of the people it knows remains.
     */
    private void replaceMembers(Long teamId, JsonNode items) {
        Set<Long> listed = new LinkedHashSet<>();
        for (JsonNode item : items) {
            if (item != null && item.has("value")) {
                // asString(null): an object or an array names nobody and is skipped, where asString()
                // threw and answered the whole PATCH 500.
                resolveUserId(item.get("value").asString(null)).ifPresent(listed::add);
            }
        }
        Set<Long> kept = new HashSet<>();
        for (TeamMemberEntity membership : members.findByTeamId(teamId)) {
            if (listed.contains(membership.getId().userId())) {
                kept.add(membership.getId().userId());
            } else {
                members.delete(membership);
            }
        }
        for (Long userId : listed) {
            if (!kept.contains(userId)) {
                members.save(new TeamMemberEntity(teamId, userId, TeamMemberEntity.Origin.SCIM));
            }
        }
    }

    /** The name a PATCH operation sets, if it sets one; refused when it is not a name. */
    private static Optional<String> renameOf(PatchOperation op) {
        JsonNode value = op.value();
        if (op.path() != null && !op.path().isBlank()) {
            if (!"displayname".equals(op.path().trim().toLowerCase(Locale.ROOT))) {
                return Optional.empty();
            }
            if (value == null || !value.isString()) {
                throw new InvalidInputException("Group displayName must be a string.");
            }
            return Optional.of(groupName(value.asString()));
        }
        if (value != null && value.isObject() && value.has("displayName")) {
            if (!value.get("displayName").isString()) {
                throw new InvalidInputException("Group displayName must be a string.");
            }
            return Optional.of(groupName(value.get("displayName").asString()));
        }
        return Optional.empty();
    }

    /**
     * Trimmed, present, and within the column: a name past it was a 500 from the insert, the
     * directory's mistake reported as the server's.
     */
    private static String groupName(String displayName) {
        String name = displayName == null ? "" : displayName.trim();
        if (name.isEmpty()) {
            throw new InvalidInputException("Group displayName cannot be blank.");
        }
        return BoundedText.within(name, TeamRules.MAX_NAME_LENGTH, "The SCIM attribute displayName");
    }

    private boolean takenByAnother(String name, Long id) {
        return teams.findByNameIgnoreCase(name).filter(other -> !other.getId().equals(id)).isPresent();
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
     * deadlock this avoids. The team is what the entry is about, and the directory is who acted.
     */
    private void recordGroup(RequestActor origin, String description, String teamName) {
        audit.record(new AuditLogService.Record(
                AuditOperation.TEAM_UPDATED, teamName, description, ACTOR, origin.ipAddress(), origin.userAgent()));
    }

    private void handleAddMembers(Long teamId, JsonNode value) {
        if (value == null) return;
        if (value.isArray()) {
            for (JsonNode item : value) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asString(null)).ifPresent(userId ->
                            members.save(new TeamMemberEntity(teamId, userId, TeamMemberEntity.Origin.SCIM)));
                }
            }
        } else if (value.isObject() && value.has("members") && value.get("members").isArray()) {
            for (JsonNode item : value.get("members")) {
                if (item.has("value")) {
                    resolveUserId(item.get("value").asString(null)).ifPresent(userId ->
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
            long id = Long.parseLong(value.trim());
            // An id no account holds is skipped, as an unknown username is: it reached the insert and
            // the foreign key answered the whole request 500.
            return users.existsById(id) ? Optional.of(id) : Optional.empty();
        } catch (NumberFormatException e) {
            return users.findByUsername(value.trim().toLowerCase(Locale.ROOT)).map(UserEntity::getId);
        }
    }

    private static GroupView viewOf(TeamEntity team, List<TeamMembership> teamMembers) {
        List<GroupMember> memberViews = new ArrayList<>(teamMembers.size());
        for (TeamMembership membership : teamMembers) {
            String display = membership.username() != null
                    ? membership.username() : String.valueOf(membership.userId());
            memberViews.add(new GroupMember(membership.userId(), display));
        }
        return new GroupView(team.getId(), team.getName(), team.getCreatedAt(), memberViews);
    }
}

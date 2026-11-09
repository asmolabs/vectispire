package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.AccountRequestRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * An administrator setting, changing and clearing another account's e-mail address.
 *
 * <p>Until 1.0.0-rc.2 the address could be written only at a creation, by the directory or by single
 * sign-on: an account made without one could never receive a checklist's contact reminders (decision 0044),
 * and a wrong one could not be corrected. A taken address at a creation was the unique key's 500.
 */
@DisplayName("the account e-mail routes")
class AccountEmailRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "a-temporary-password-of-length";

    @Autowired
    private UserRepository users;

    @Autowired
    private AuditLogRepository audit;

    @Autowired
    private AccountRequestRepository requests;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("an address is set, changed and cleared, and each is audited without the address")
    void setChangeClear() throws Exception {
        long id = account("ella");

        change(asAdmin(), id, Map.of("email", "  ella@example.org "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("ella@example.org"))
                .andExpect(jsonPath("$.scimManaged").value(false));
        assertThat(emailOf(id)).as("trimmed").isEqualTo("ella@example.org");

        change(asAdmin(), id, Map.of("email", "ella.new@example.org"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("ella.new@example.org"));
        assertThat(emailOf(id)).isEqualTo("ella.new@example.org");

        change(asAdmin(), id, Map.of("email", "  "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").doesNotExist());
        assertThat(emailOf(id)).as("blank clears, and stores null rather than the empty string").isNull();

        assertThat(entriesAbout(id))
                .containsExactly("Account ella: e-mail address set", "Account ella: e-mail address changed",
                        "Account ella: e-mail address cleared");
        assertThat(audit.findAllByOrderByTimestampAscIdAsc())
                .extracting(AuditLogEntity::getDescription)
                .noneMatch(description -> description.contains("example.org"));
    }

    @Test
    @DisplayName("an absent address, or the one the account holds, changes nothing and writes no entry")
    void unchangedIsNoChange() throws Exception {
        long id = account("fred");
        change(asAdmin(), id, Map.of("email", "fred@example.org")).andExpect(status().isOk());

        change(asAdmin(), id, Map.of("role", Role.USER.name())).andExpect(status().isOk());
        change(asAdmin(), id, Map.of("email", "fred@example.org")).andExpect(status().isOk());

        assertThat(emailOf(id)).isEqualTo("fred@example.org");
        assertThat(entriesAbout(id)).containsExactly("Account fred: e-mail address set");
    }

    @Test
    @DisplayName("an address that does not read as one, or past its column, is a 400 and changes nothing")
    void malformedIsRefused() throws Exception {
        long id = account("gina");
        change(asAdmin(), id, Map.of("email", "gina@example.org")).andExpect(status().isOk());

        for (String refused : List.of("gina", "gina at example.org", "gina@example", "gi na@example.org",
                "gina@example.org, eve@example.org", "gina@example.org\nBcc: eve@example.org",
                "a".repeat(251) + "@x.io")) {
            change(asAdmin(), id, Map.of("email", refused))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("invalid-request"));
        }
        assertThat(emailOf(id)).isEqualTo("gina@example.org");
    }

    @Test
    @DisplayName("an address another account holds is a 400, at a change and at a creation, letter case aside")
    void takenIsRefused() throws Exception {
        long holder = account("hank");
        change(asAdmin(), holder, Map.of("email", "hank@example.org")).andExpect(status().isOk());
        long other = account("ivy");

        ResultActions refused = change(asAdmin(), other, Map.of("email", "Hank@Example.org"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid-request"));
        assertThat(detailOf(refused.andReturn())).contains("already used by another account");
        assertThat(emailOf(other)).isNull();

        create(asAdmin(), Map.of("username", "jack", "password", PASSWORD, "email", "hank@example.org"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("invalid-request"));
        assertThat(users.findByUsername("jack")).as("no longer the unique key's 500").isEmpty();
    }

    @Test
    @DisplayName("a creation checks the address's shape and keeps it trimmed")
    void creationChecksTheShape() throws Exception {
        create(asAdmin(), Map.of("username", "kate", "password", PASSWORD, "email", "kate"))
                .andExpect(status().isBadRequest());
        assertThat(users.findByUsername("kate")).isEmpty();

        create(asAdmin(), Map.of("username", "kate", "password", PASSWORD, "email", " kate@example.org "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("kate@example.org"));
    }

    @Test
    @DisplayName("an account the directory writes refuses a change of its address with 409 managed-by-directory")
    void directoryManagedIsRefused() throws Exception {
        long id = account("lena");
        UserEntity lena = users.findById(id).orElseThrow();
        lena.setEmail("lena@example.org");
        lena.setScimManaged(true);
        users.save(lena);

        for (String refused : new String[] {"lena@elsewhere.org", ""}) {
            change(asAdmin(), id, Map.of("email", refused))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.type").value("urn:vectispire:problem:managed-by-directory"))
                    .andExpect(jsonPath("$.code").value("managed-by-directory"));
        }
        assertThat(emailOf(id)).isEqualTo("lena@example.org");

        // Resending the address it holds is no change, so the rest of the form applies.
        change(asAdmin(), id, Map.of("email", "lena@example.org", "role", Role.AUDITOR.name()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scimManaged").value(true))
                .andExpect(jsonPath("$.role").value(Role.AUDITOR.name()));
    }

    @Test
    @DisplayName("a directory write marks the account, which then refuses an administrator's address")
    void provisioningMarksTheAccount() throws Exception {
        mvc.perform(authenticated(post("/scim/v2/Users"), asScim())
                        .contentType(MediaType.parseMediaType("application/scim+json"))
                        .content(write(Map.of("userName", "mona",
                                "emails", List.of(Map.of("value", "mona@example.org", "primary", true))))))
                .andExpect(status().isCreated());
        long id = users.findByUsername("mona").orElseThrow().getId();
        assertThat(users.findById(id).orElseThrow().getScimManaged()).isTrue();

        change(asAdmin(), id, Map.of("email", "mona@elsewhere.org")).andExpect(status().isConflict());
    }

    @Test
    @DisplayName("an account that is not an administrator cannot change an address")
    void administratorsOnly() throws Exception {
        long id = account("nina");

        change(asCiso(), id, Map.of("email", "nina@example.org")).andExpect(status().isForbidden());
        change(asReader(), id, Map.of("email", "nina@example.org")).andExpect(status().isForbidden());
        assertThat(emailOf(id)).isNull();
    }

    @Test
    @DisplayName("under four-eyes, an address sent with a filed role raise applies at once")
    void appliesBesideAFiledRaise() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "true");
        String alice = tokenFor("alice", Role.ADMIN, false);
        tokenFor("bob", Role.ADMIN, false);
        long id = account("olga");

        change(alice, id, Map.of("role", Role.ADMIN.name(), "email", "olga@example.org"))
                .andExpect(status().isAccepted());

        assertThat(requests.findAll()).singleElement()
                .satisfies(request -> assertThat(request.getRequestedRole()).isEqualTo(Role.ADMIN.name()));
        UserEntity olga = users.findById(id).orElseThrow();
        assertThat(olga.getEmail()).isEqualTo("olga@example.org");
        assertThat(olga.getRole()).as("the raise waits").isEqualTo(Role.USER.name());
    }

    private long account(String username) {
        tokenFor(username, Role.USER, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private String emailOf(long id) {
        return users.findById(id).orElseThrow().getEmail();
    }

    private List<String> entriesAbout(long id) {
        return audit.findAllByOrderByTimestampAscIdAsc().stream()
                .filter(entry -> entry.getOperationType().equals(AuditOperation.USER_UPDATED.name()))
                .filter(entry -> String.valueOf(id).equals(entry.getResourceId()))
                .map(AuditLogEntity::getDescription)
                .toList();
    }

    private ResultActions create(String token, Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)), token));
    }

    private ResultActions change(String token, long account, Map<String, String> change) throws Exception {
        return mvc.perform(authenticated(patch("/api/v1/users/" + account)
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(new HashMap<>(change))), token));
    }
}

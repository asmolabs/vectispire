package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A project's checklist profiles linked to its accounts, through the real routes (decision 0044): the
 * profiles read from the contact column as a real template writes it, the accounts a profile may name,
 * the link and its audit, the warnings a link turns into when its account changes — and every route
 * refusing a project the caller does not see whole in the words of one that does not exist.
 */
@DisplayName("checklist contacts, through the routes")
class ChecklistContactsRoutesTest extends ChecklistContactsTestBase {

    @Nested
    @DisplayName("the profiles")
    class Profiles {

        @Test
        @DisplayName("none before the project has a checklist")
        void noneBeforeAChecklist() throws Exception {
            JsonNode contacts = contacts(developer.token());

            assertThat(contacts.at("/projectId").asLong()).isEqualTo(project);
            assertThat(contacts.at("/revision").isNull()).isTrue();
            assertThat(contacts.at("/draft").asBoolean()).isFalse();
            assertThat(contacts.at("/profiles")).isEmpty();
        }

        @Test
        @DisplayName("every value of the column but AUTO, each once, as first written, with its lines to fill in")
        void readFromTheColumn() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());

            JsonNode contacts = contacts(developer.token());

            assertThat(contacts.at("/revision").asInt()).isEqualTo(1);
            assertThat(contacts.at("/draft").asBoolean()).isTrue();
            List<String> keys = new ArrayList<>();
            contacts.at("/profiles").forEach(profile -> keys.add(profile.at("/profile").asText()));
            assertThat(keys).as("the column's order; AUTO is no profile").containsExactly("PO", "BA", "ARCH");
            assertThat(profile(contacts, "ARCH").at("/label").asText()).as("as first written").isEqualTo("Arch");
            // "PO / BA" is both profiles' line; "Arch" and "ARCH" are one profile's two lines.
            assertThat(profile(contacts, "PO").at("/openLines").asInt()).isEqualTo(2);
            assertThat(profile(contacts, "BA").at("/openLines").asInt()).isEqualTo(1);
            assertThat(profile(contacts, "ARCH").at("/openLines").asInt()).isEqualTo(2);
            assertThat(profile(contacts, "PO").at("/accountId").isNull()).isTrue();
            assertThat(profile(contacts, "PO").at("/warning").isNull()).isTrue();
        }

        @Test
        @DisplayName("an answered line is filled in, for each profile it names")
        void anAnswerFillsALineIn() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            answerYes(developer, lineIds(developer).get(1)); // "PO / BA"

            JsonNode contacts = contacts(developer.token());

            assertThat(profile(contacts, "PO").at("/openLines").asInt()).isEqualTo(1);
            assertThat(profile(contacts, "BA").at("/openLines").asInt()).isZero();
        }
    }

    @Test
    @DisplayName("a carried answer waiting for confirmation is still to fill in")
    void aCarriedAnswerIsStillToFillIn() throws Exception {
        openChecklist(developer).andExpect(status().isCreated());
        List<Long> lines = lineIds(developer);
        answerYes(developer, lines.get(2));
        answerYes(developer, lines.get(4));
        assertThat(profile(contacts(developer.token()), "ARCH").at("/openLines").asInt()).isZero();

        // What a move to a version that reworded the line leaves: the answer carried, waiting for a person.
        jdbc.update("update t_checklist_answer set needs_confirmation = true where item_id = ?", lines.get(4));

        assertThat(profile(contacts(developer.token()), "ARCH").at("/openLines").asInt()).isEqualTo(1);
    }

    @Nested
    @DisplayName("linking")
    class Linking {

        @Test
        @DisplayName("links a profile by any spelling, names the account, says it has no address, and audits it")
        void links() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());

            JsonNode linked = read(link(champion.token(), "arch", developer.id()).andExpect(status().isOk()));

            JsonNode arch = profile(linked, "ARCH");
            assertThat(arch.at("/accountId").asLong()).isEqualTo(developer.id());
            assertThat(arch.at("/accountName").isNull()).as("no display name: never the user name").isTrue();
            assertThat(arch.at("/warning").asText()).as("nothing to write to").isEqualTo("no_email");
            // A reader who cannot relink the profile is told that the account would not be reminded, not why.
            assertThat(profile(contacts(asAuditor()), "ARCH").at("/warning").asText()).isEqualTo("not_reminded");
            // And so is the platform governor, who reads every checklist and answers none.
            assertThat(profile(contacts(account(Role.SUPERUSER).token()), "ARCH").at("/warning").asText())
                    .isEqualTo("not_reminded");
            assertThat(contacts(asAuditor()).toString()).doesNotContain(developer.name());
            assertThat(entries("CHECKLIST_CONTACT_CHANGED")).singleElement().satisfies(entry -> {
                assertThat(entry.getUserId()).isEqualTo(champion.name());
                assertThat(entry.getResourceId()).isEqualTo(project + "/contacts/ARCH");
                assertThat(entry.getDescription()).contains("Arch", "\"Checkout\"", "account " + developer.id())
                        // By id: the user name is how the account signs in, and the log is read by more people.
                        .doesNotContain(developer.name());
            });

            change(developer, row -> {
                row.setEmail("developer@example.org");
                row.setDisplayName("Development lead");
            });
            JsonNode reachable = profile(contacts(asAuditor()), "ARCH");
            assertThat(reachable.at("/warning").isNull()).isTrue();
            assertThat(reachable.at("/accountName").asText()).isEqualTo("Development lead");
        }

        @Test
        @DisplayName("linking the same account again changes nothing, and another replaces it")
        void relinking() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            // An id past 127: two boxed ids compared by reference agree below it, and only below it — the
            // comparison passed alone and failed in the full suite, whose accounts had numbered further.
            jdbc.execute("alter table t_user auto_increment = 100000");
            long contact = accountWithoutSession(Role.USER, null);
            assertThat(contact).isGreaterThan(127);
            link(champion.token(), "PO", contact).andExpect(status().isOk());
            link(champion.token(), "po", contact).andExpect(status().isOk());
            assertThat(entries("CHECKLIST_CONTACT_CHANGED")).as("nothing changed the second time").hasSize(1);

            JsonNode replaced = read(link(developer.token(), "PO", champion.id()).andExpect(status().isOk()));

            assertThat(profile(replaced, "PO").at("/accountId").asLong()).isEqualTo(champion.id());
            assertThat(entries("CHECKLIST_CONTACT_CHANGED")).hasSize(2)
                    .anySatisfy(entry -> assertThat(entry.getDescription()).contains("in place of account " + contact));
        }

        @Test
        @DisplayName("an unlinked profile goes back to nobody, audited once")
        void unlinks() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            link(champion.token(), "BA", developer.id()).andExpect(status().isOk());

            JsonNode unlinked = read(unlink(champion.token(), "ba").andExpect(status().isOk()));
            unlink(champion.token(), "BA").andExpect(status().isOk());

            assertThat(profile(unlinked, "BA").at("/accountId").isNull()).isTrue();
            assertThat(entries("CHECKLIST_CONTACT_CHANGED")).hasSize(2)
                    .anySatisfy(entry -> assertThat(entry.getDescription()).contains("unlinked from account " + developer.id()));
        }

        @Test
        @DisplayName("refuses a profile the column does not name, AUTO included, and an account that cannot fill it in")
        void refusals() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());

            assertThat(detailOf(link(champion.token(), "QA", developer.id()).andExpect(status().isNotFound()).andReturn()))
                    .isEqualTo("The checklist of project \"Checkout\" names no profile \"QA\".");
            link(champion.token(), "AUTO", developer.id()).andExpect(status().isNotFound());
            link(champion.token(), "PO", null).andExpect(status().isBadRequest());

            Account auditor = account(Role.AUDITOR);
            Account inactive = account(Role.USER);
            change(inactive, row -> row.setIsActive(false));
            String sentence = "cannot be linked: it does not exist, is deactivated, or cannot fill in this project's checklist.";
            for (long refused : List.of(auditor.id(), inactive.id(), account(Role.SUPERUSER).id(), developer.id() + 100_000)) {
                assertThat(detailOf(link(champion.token(), "PO", refused).andExpect(status().isBadRequest()).andReturn()))
                        .isEqualTo("Account " + refused + " " + sentence);
            }
            assertThat(entries("CHECKLIST_CONTACT_CHANGED")).isEmpty();
        }

        @Test
        @DisplayName("refuses, under assigned visibility, an account that does not see the whole project")
        void refusesAPartialAccount() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            restrict();
            Account partial = account(Role.USER);
            grant(partial.id(), "repository", firstRepository);
            Account whole = account(Role.USER);
            grant(whole.id(), "project", project);

            link(asAdmin(), "PO", partial.id()).andExpect(status().isBadRequest());
            link(asAdmin(), "PO", whole.id()).andExpect(status().isOk());
        }

        @Test
        @DisplayName("a link whose account changed since says why it reminds nobody")
        void warnings() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            long contact = accountWithoutSession(Role.USER, "contact@example.org");
            link(champion.token(), "PO", contact).andExpect(status().isOk());
            assertThat(profile(contacts(asAdmin()), "PO").at("/warning").isNull()).isTrue();

            restrict();
            assertThat(profile(contacts(asAdmin()), "PO").at("/warning").asText()).isEqualTo("cannot_fill");
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TARGET_VISIBILITY, "everyone");

            var row = users.findById(contact).orElseThrow();
            row.setIsActive(false);
            users.save(row);
            assertThat(profile(contacts(asAdmin()), "PO").at("/warning").asText()).isEqualTo("account_inactive");

            users.deleteById(contact);
            JsonNode gone = profile(contacts(asAdmin()), "PO");
            assertThat(gone.at("/warning").asText()).isEqualTo("account_gone");
            assertThat(gone.at("/accountId").asLong()).as("the link is kept, to be replaced").isEqualTo(contact);
            assertThat(gone.at("/accountName").isNull()).isTrue();
        }
    }

    @Nested
    @DisplayName("the candidates")
    class Candidates {

        @Test
        @DisplayName("the active accounts that write and see the whole project, by id and a name that is no address")
        void candidates() throws Exception {
            Account auditor = account(Role.AUDITOR);
            Account inactive = account(Role.USER);
            change(inactive, row -> row.setIsActive(false));
            Account named = account(Role.USER);
            change(named, row -> row.setDisplayName("Ada Lovelace"));
            Account addressed = account(Role.USER);
            change(addressed, row -> {
                row.setUsername("ada." + System.nanoTime() + "@example.org");
                row.setDisplayName("ada@example.org");
                row.setEmail("ada@example.org");
            });

            JsonNode candidates = read(mvc.perform(authenticated(get(contactsPath() + "/candidates"), developer.token()))
                    .andExpect(status().isOk()));

            List<Long> ids = new ArrayList<>();
            candidates.forEach(candidate -> ids.add(candidate.at("/accountId").asLong()));
            assertThat(ids).contains(developer.id(), champion.id(), named.id(), addressed.id())
                    .doesNotContain(auditor.id(), inactive.id());
            for (JsonNode candidate : candidates) {
                assertThat(candidate.has("email")).isFalse();
                long id = candidate.at("/accountId").asLong();
                if (id == named.id()) {
                    assertThat(candidate.at("/name").asText()).isEqualTo("Ada Lovelace");
                }
                if (id == addressed.id()) {
                    assertThat(candidate.at("/name").isNull()).as("neither name may be printed").isTrue();
                }
            }
            assertThat(candidates.toString()).doesNotContain("@example.org");
            // An account with no display name is named by nobody but its id: the user name is how it signs in.
            for (JsonNode candidate : candidates) {
                if (candidate.at("/accountId").asLong() == developer.id()) {
                    assertThat(candidate.at("/name").isNull()).isTrue();
                }
            }
            assertThat(candidates.toString()).doesNotContain(developer.name(), champion.name());
        }

        @Test
        @DisplayName("under assigned visibility, only those who see the whole project")
        void underAssignedVisibility() throws Exception {
            restrict();
            Account partial = account(Role.USER);
            grant(partial.id(), "repository", firstRepository);
            Account whole = account(Role.USER);
            grant(whole.id(), "repository", firstRepository);
            grant(whole.id(), "repository", secondRepository);

            JsonNode candidates = read(mvc.perform(authenticated(get(contactsPath() + "/candidates"), asAdmin()))
                    .andExpect(status().isOk()));

            List<Long> ids = new ArrayList<>();
            candidates.forEach(candidate -> ids.add(candidate.at("/accountId").asLong()));
            assertThat(ids).contains(whole.id()).doesNotContain(partial.id(), developer.id());
        }
    }

    @Nested
    @DisplayName("the whole project, or nothing")
    class Visibility {

        @Test
        @DisplayName("a reader who sees part of the project is answered as if it did not exist, on every route")
        void aPartialReaderIsAnsweredNotFound() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            restrict();
            Account partial = account(Role.USER);
            grant(partial.id(), "repository", firstRepository);

            List<ResultActions> refused = List.of(
                    mvc.perform(authenticated(get(contactsPath()), partial.token())),
                    mvc.perform(authenticated(get(contactsPath() + "/candidates"), partial.token())),
                    link(partial.token(), "PO", partial.id()),
                    unlink(partial.token(), "PO"));
            for (ResultActions result : refused) {
                MvcResult answered = result.andExpect(status().isNotFound()).andReturn();
                assertThat(detailOf(answered)).isEqualTo("Project not found.");
            }
            assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/projects/" + (project + 1000) + "/checklists/contacts"),
                    partial.token())).andExpect(status().isNotFound()).andReturn())).isEqualTo("Project not found.");
        }

        @Test
        @DisplayName("reading is any account's, the rest a writer's, and nothing is anonymous")
        void theRoles() throws Exception {
            openChecklist(developer).andExpect(status().isCreated());
            String auditor = asAuditor();

            mvc.perform(authenticated(get(contactsPath()), auditor)).andExpect(status().isOk());
            mvc.perform(authenticated(get(contactsPath() + "/candidates"), auditor)).andExpect(status().isForbidden());
            link(auditor, "PO", developer.id()).andExpect(status().isForbidden());
            unlink(auditor, "PO").andExpect(status().isForbidden());
            mvc.perform(get(contactsPath())).andExpect(status().isUnauthorized());
        }
    }

    @Test
    @DisplayName("a deleted project takes its links with it")
    void aDeletedProjectTakesItsLinks() throws Exception {
        openChecklist(developer).andExpect(status().isCreated());
        link(champion.token(), "PO", developer.id()).andExpect(status().isOk());

        mvc.perform(authenticated(delete("/api/v1/projects/" + project), asAdmin())).andExpect(status().isNoContent());

        assertThat(contactRows()).isZero();
    }

    private long contactRows() {
        return jdbc.queryForObject("select count(*) from t_checklist_contact where project_id = ?", Long.class, project);
    }

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbc;
}

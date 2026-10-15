package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.ScimProvisioningService;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * SCIM's {@code /Users} and {@code /Groups} pages, as RFC 7644 §3.4.2.4 pages them.
 *
 * <p><b>Asked neither parameter, every resource, as before</b>: {@code totalResults} and {@code itemsPerPage}
 * the whole count, {@code startIndex} 1. Asked a page, the resources from the 1-based {@code startIndex}, at
 * most {@code count}, with {@code totalResults} still the whole count. Out-of-range values are interpreted as
 * the RFC says, never refused: an identity provider answered a 400 stops synchronising.
 */
@DisplayName("the SCIM lists' pages")
class ScimPagingRoutesTest extends ApiTestBase {

    @Autowired
    private TeamRepository teams;

    @Autowired
    private UserRepository users;

    @Test
    @DisplayName("groups: asked nothing, every group by id; asked a page, that list cut from startIndex")
    void groupsPage() throws Exception {
        List<String> filed = new ArrayList<>();
        for (String name : List.of("Gamma", "Alpha", "Beta", "Delta", "Epsilon")) {
            filed.add(String.valueOf(team(name)));
        }
        String admin = asAdmin();

        JsonNode every = read("/scim/v2/Groups", admin);
        assertThat(ids(every)).containsExactlyElementsOf(filed);
        assertListing(every, 5, 1, 5);

        JsonNode second = read("/scim/v2/Groups?startIndex=2&count=2", admin);
        assertThat(ids(second)).containsExactly(filed.get(1), filed.get(2));
        assertListing(second, 5, 2, 2);
        assertThat(ids(read("/scim/v2/Groups?startIndex=4&count=2", admin))).containsExactly(filed.get(3), filed.get(4));
        // The row a page holds is the row the whole list holds.
        assertThat(second.path("Resources").get(0)).isEqualTo(every.path("Resources").get(1));

        // A startIndex alone answers every group from there; past the end, none, with the total still said.
        assertThat(ids(read("/scim/v2/Groups?startIndex=4", admin))).containsExactly(filed.get(3), filed.get(4));
        JsonNode past = read("/scim/v2/Groups?startIndex=9&count=2", admin);
        assertThat(ids(past)).isEmpty();
        assertListing(past, 5, 9, 0);
    }

    @Test
    @DisplayName("groups and users: out-of-range values are read as the RFC says, never refused")
    void outOfRangeIsInterpreted() throws Exception {
        for (String name : List.of("One", "Two", "Three")) {
            team(name);
        }
        String admin = asAdmin();

        // startIndex below 1 is 1; a negative count is 0, and 0 answers the total alone.
        JsonNode below = read("/scim/v2/Groups?startIndex=0&count=1", admin);
        assertListing(below, 3, 1, 1);
        assertListing(read("/scim/v2/Groups?startIndex=-5&count=1", admin), 3, 1, 1);
        assertListing(read("/scim/v2/Groups?count=0", admin), 3, 1, 0);
        assertListing(read("/scim/v2/Groups?count=-1", admin), 3, 1, 0);
        // Past the ceiling, the ceiling's worth — here every group.
        assertListing(read("/scim/v2/Groups?count=100000", admin), 3, 1, 3);

        long accounts = users.count();
        assertListing(read("/scim/v2/Users?startIndex=0&count=-1", admin), (int) accounts, 1, 0);
    }

    @Test
    @DisplayName("users: asked nothing, every account by username; asked a page, that list cut; a filter pages too")
    void usersPage() throws Exception {
        String admin = asAdmin();
        for (int i = 0; i < 4; i++) {
            tokenFor("scim-pager-" + i + "-" + System.nanoTime(), Role.USER, false);
        }
        int accounts = (int) users.count();

        JsonNode every = read("/scim/v2/Users", admin);
        assertListing(every, accounts, 1, accounts);
        // By username, in the database's collation, which is what the pages are cut from.
        List<String> names = userNames(every);

        List<String> paged = new ArrayList<>();
        for (int start = 1; start <= accounts; start += 2) {
            JsonNode page = read("/scim/v2/Users?startIndex=" + start + "&count=2", admin);
            assertThat(page.path("totalResults").asInt()).isEqualTo(accounts);
            assertThat(page.path("startIndex").asInt()).isEqualTo(start);
            paged.addAll(userNames(page));
        }
        assertThat(paged).containsExactlyElementsOf(names);

        String one = names.get(1);
        JsonNode filtered = filtered("userName eq \"" + one + "\"", "1", "5", admin);
        assertListing(filtered, 1, 1, 1);
        assertThat(userNames(filtered)).containsExactly(one);
        assertListing(filtered("userName eq \"" + one + "\"", "2", "5", admin), 1, 2, 0);
    }

    @Test
    @DisplayName("a page's count is bounded by the figure every list route pages by")
    void countIsBounded() {
        List<Integer> rows = IntStream.range(0, 700).boxed().toList();
        ScimProvisioningService.Page<Integer> page = ScimProvisioningService.Page.of(rows, 101, 1000);
        assertThat(page.resources()).hasSize(500).startsWith(100);
        assertThat(page.totalResults()).isEqualTo(700);
        assertThat(ScimProvisioningService.Page.of(rows, null, null).resources()).hasSize(700);
        assertThat(ScimProvisioningService.Page.of(rows, Integer.MAX_VALUE, Integer.MAX_VALUE).resources()).isEmpty();
    }

    private static void assertListing(JsonNode listing, int totalResults, int startIndex, int itemsPerPage) {
        assertThat(listing.path("schemas").get(0).asText()).isEqualTo("urn:ietf:params:scim:api:messages:2.0:ListResponse");
        assertThat(listing.path("totalResults").asInt()).as("totalResults").isEqualTo(totalResults);
        assertThat(listing.path("startIndex").asInt()).as("startIndex").isEqualTo(startIndex);
        assertThat(listing.path("itemsPerPage").asInt()).as("itemsPerPage").isEqualTo(itemsPerPage);
        assertThat(listing.path("Resources").size()).as("Resources").isEqualTo(itemsPerPage);
    }

    private JsonNode read(String route, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get(route), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private JsonNode filtered(String filter, String startIndex, String count, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/scim/v2/Users")
                                .param("filter", filter).param("startIndex", startIndex).param("count", count), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static List<String> ids(JsonNode listing) {
        return StreamSupport.stream(listing.path("Resources").spliterator(), false)
                .map(node -> node.path("id").asText()).toList();
    }

    private static List<String> userNames(JsonNode listing) {
        return StreamSupport.stream(listing.path("Resources").spliterator(), false)
                .map(node -> node.path("userName").asText()).toList();
    }

    private long team(String name) {
        TeamEntity team = new TeamEntity();
        team.setName(name + "-" + System.nanoTime());
        team.setCreatedAt(Instant.now());
        return teams.save(team).getId();
    }
}

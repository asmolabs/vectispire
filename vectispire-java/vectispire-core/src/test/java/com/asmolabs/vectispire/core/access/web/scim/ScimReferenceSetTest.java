package com.asmolabs.vectispire.core.access.web.scim;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.access.AuthService;
import com.asmolabs.vectispire.core.access.ScimProvisioningService;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamMemberRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.access.web.scim.dto.ScimErrorResponse;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * What {@link ScimProvisioningService} decides before it reads a row — the answers the Rust control plane's SCIM
 * service is held to ({@code vectispire-rust/reference/access/scim/}, read by {@code vectispire-domain}'s
 * {@code scim_reference_set.rs}).
 *
 * <p><b>The service answers, never a restatement of it.</b> Its repositories are mocks that record what they are
 * asked, so each answer is the lookup the real service made: the filters a users' list evaluates and the account
 * each one looks up — or the 400 the controller's own handler writes for one it refuses, {@code scimType} and
 * {@code detail} included — the pages {@code Page.of} cuts, how a PATCH names a group's member (Jackson 3's
 * {@code asString()}, {@code Long.parseLong}, the root locale's lower case) and which member a {@code remove} path
 * takes away. A refusal or a filter read differently is a directory synchronising against another answer.
 *
 * <p>Checked on every build: without {@code -Dvectispire.rust.reference.write=true} the test fails when an answer
 * differs from the committed file.
 */
class ScimReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The HTTP layer's Jackson, which builds a PATCH's {@code value}. */
    private static final tools.jackson.databind.ObjectMapper JSON3 =
            tools.jackson.databind.json.JsonMapper.builder().build();

    private static final RequestActor DIRECTORY = new RequestActor(null, null, null);

    /** The account a username names, and the team every PATCH is made to. */
    private static final long NAMED = 42L;

    private static final long TEAM = 1L;

    @Test
    void theAnswersTheRustScimServiceIsHeldTo() throws Exception {
        String text = Files.readString(
                Path.of(System.getProperty("vectispire.rust.reference")).resolve("access/scim/inputs.json"),
                StandardCharsets.UTF_8);
        JsonNode inputs = JSON.readTree(text);
        ObjectNode answers = RustReference.object();

        filters(inputs.path("filters"), answers.putArray("filters"));
        pages(inputs.path("pages"), answers.putArray("pages"));
        memberItems(JSON3.readTree(text).path("memberItems"), answers.putArray("memberItems"));
        removalPaths(inputs.path("removalPaths"), answers.putArray("removalPaths"));

        RustReference.expect("access/scim/java-answers.json", answers, ScimReferenceSetTest.class);
    }

    /** The list's filter: the lookup it made, or the controller's 400. */
    private static void filters(JsonNode inputs, ArrayNode answers) {
        for (JsonNode input : inputs) {
            String filter = input.isNull() ? null : input.asText();
            List<String> lookups = new ArrayList<>();
            UserRepository users = mock(UserRepository.class);
            when(users.findAllByOrderByUsernameAsc()).thenAnswer(call -> {
                lookups.add("all");
                return List.of();
            });
            when(users.findByUsername(anyString())).thenAnswer(call -> {
                lookups.add("userName " + call.getArgument(0));
                return Optional.empty();
            });
            when(users.findByKeycloakId(anyString())).thenAnswer(call -> {
                lookups.add("externalId " + call.getArgument(0));
                return Optional.empty();
            });
            ScimUsersController controller = new ScimUsersController(service(users, mock(TeamRepository.class),
                    mock(TeamMemberRepository.class)));

            ObjectNode answer = answers.addObject();
            answer.put("input", filter);
            try {
                controller.listUsers(filter, null, null);
                ArrayNode made = answer.putArray("lookups");
                lookups.forEach(made::add);
            } catch (ScimProvisioningService.InvalidFilterException refused) {
                ResponseEntity<ScimErrorResponse> response = controller.handleInvalidFilter(refused);
                ScimErrorResponse body = response.getBody();
                answer.put("httpStatus", response.getStatusCode().value());
                answer.put("status", body.status());
                answer.put("scimType", body.scimType());
                answer.put("detail", body.detail());
            }
        }
    }

    /** {@code Page.of} over the identifiers 0 to size - 1: the first it answers, how many, the total and the start. */
    private static void pages(JsonNode inputs, ArrayNode answers) {
        for (JsonNode input : inputs) {
            int size = input.path("size").asInt();
            Integer startIndex = input.path("startIndex").isNull() ? null : input.path("startIndex").asInt();
            Integer count = input.path("count").isNull() ? null : input.path("count").asInt();
            ScimProvisioningService.Page<Integer> page = ScimProvisioningService.Page.of(
                    IntStream.range(0, size).boxed().toList(), startIndex, count);

            ObjectNode answer = answers.addObject();
            answer.set("input", input);
            if (page.resources().isEmpty()) {
                answer.putNull("first");
            } else {
                answer.put("first", page.resources().get(0));
            }
            answer.put("size", page.resources().size());
            answer.put("totalResults", page.totalResults());
            answer.put("startIndex", page.startIndex());
        }
    }

    /**
     * One entry of a PATCH {@code add} to {@code members}: the account lookups it made — or the exception that left
     * the service, which no SCIM handler catches and the application answers 500.
     */
    private static void memberItems(tools.jackson.databind.JsonNode inputs, ArrayNode answers) throws Exception {
        for (tools.jackson.databind.JsonNode item : inputs) {
            List<String> lookups = new ArrayList<>();
            ScimProvisioningService service = groupService(lookups);
            tools.jackson.databind.node.ArrayNode value = JSON3.createArrayNode();
            value.add(item);

            ObjectNode answer = answers.addObject();
            answer.set("input", JSON.readTree(JSON3.writeValueAsString(item)));
            try {
                service.patchGroup(TEAM, List.of(new ScimProvisioningService.PatchOperation("add", "members", value)),
                        DIRECTORY);
                ArrayNode made = answer.putArray("lookups");
                lookups.forEach(made::add);
            } catch (RuntimeException unhandled) {
                answer.put("unhandled", unhandled.getClass().getSimpleName());
            }
        }
    }

    /** A PATCH {@code remove}'s path: the lookups it made, then {@code one} or {@code everyone} for what it removed. */
    private static void removalPaths(JsonNode inputs, ArrayNode answers) {
        for (JsonNode input : inputs) {
            String path = input.isNull() ? null : input.asText();
            List<String> lookups = new ArrayList<>();
            ScimProvisioningService service = groupService(lookups);

            ObjectNode answer = answers.addObject();
            answer.put("input", path);
            service.patchGroup(TEAM, List.of(new ScimProvisioningService.PatchOperation("remove", path, null)),
                    DIRECTORY);
            ArrayNode made = answer.putArray("lookups");
            lookups.forEach(made::add);
        }
    }

    /**
     * The service over one team, whose every identifier exists and whose every username is account {@link #NAMED}:
     * what is recorded is what the service asked, and what it removed.
     */
    private static ScimProvisioningService groupService(List<String> lookups) {
        UserRepository users = mock(UserRepository.class);
        when(users.existsById(anyLong())).thenAnswer(call -> {
            lookups.add("id " + call.getArgument(0));
            return true;
        });
        when(users.findByUsername(anyString())).thenAnswer(call -> {
            lookups.add("userName " + call.getArgument(0));
            UserEntity account = new UserEntity();
            account.setId(NAMED);
            account.setUsername(call.getArgument(0));
            return Optional.of(account);
        });
        TeamEntity team = new TeamEntity();
        team.setId(TEAM);
        team.setName("Platform");
        TeamRepository teams = mock(TeamRepository.class);
        when(teams.findById(TEAM)).thenReturn(Optional.of(team));
        TeamMemberRepository members = mock(TeamMemberRepository.class);
        when(members.findMembershipsOf(anyLong())).thenReturn(List.of());
        doAnswer(call -> {
            lookups.add("remove one");
            return null;
        }).when(members).deleteById(any());
        when(members.deleteByTeamId(anyLong())).thenAnswer(call -> {
            lookups.add("remove everyone");
            return 0;
        });
        return service(users, teams, members);
    }

    @SuppressWarnings("unchecked")
    private static ScimProvisioningService service(UserRepository users, TeamRepository teams, TeamMemberRepository members) {
        TransactionTemplate transactions = mock(TransactionTemplate.class);
        when(transactions.execute(any())).thenAnswer(call ->
                ((TransactionCallback<Object>) call.getArgument(0)).doInTransaction(mock(TransactionStatus.class)));
        return new ScimProvisioningService(users, teams, members, mock(AuthService.class), mock(AuditLogService.class),
                transactions, Clock.fixed(Instant.parse("2026-10-29T10:00:00Z"), ZoneOffset.UTC), false);
    }
}

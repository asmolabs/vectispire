package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.common.domain.scheduling.Schedules;
import com.asmolabs.vectispire.common.domain.targets.AssetTier;
import com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist;
import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.domain.targets.RepositoryIdentity;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.RustReference;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * What the targets module's rules answer — the reference set the Rust port ({@code vectispire-cp-targets} and the
 * additions to {@code vectispire_domain}) is held to, written before the port.
 *
 * <p><b>Why these.</b> Each is a refusal an operator reads or a value a row stores: the bounded fields' sentences,
 * which a form shows as they are; the repository identity, whose guard is a unique index, so that a Rust instance
 * computing it differently would accept the twin a Java instance refuses, or the reverse, during a rolling switch;
 * the schedule an operator chooses, which decides whether a target is ever scanned; the image reference a {@code
 * docker pull} receives; the case-insensitive order the solutions tree is sorted in, which is Java's
 * {@code String.CASE_INSENSITIVE_ORDER} over UTF-16 units and not any Rust collation.
 *
 * <p>Inputs carry the cases that break naive ports: astral characters at a length limit (two UTF-16 units each),
 * the no-break space Java's {@code trim} keeps, mixed case, an SCP URL with a port-looking path, a digest tag.
 */
class TargetRulesReferenceSetTest {

    private static final String NBSP = " ";
    private static final String GRIN = "😀";

    @Test
    void theAnswersTheRustPortIsHeldTo() {
        ObjectNode out = RustReference.object();
        out.set("boundedText", boundedText());
        out.set("repositoryUrl", repositoryUrl());
        out.set("maskedForm", maskedForm());
        out.set("repositoryIdentity", repositoryIdentity());
        out.set("imageReference", imageReference());
        out.set("assetTier", assetTier());
        out.set("requiredLabel", requiredLabel());
        out.set("listWindow", listWindow());
        out.set("gitHostAllowlist", gitHostAllowlist());
        out.set("scheduleChoice", scheduleChoice());
        out.set("validatedCron", validatedCron());
        out.set("inForce", inForce());
        out.set("caseInsensitiveOrder", caseInsensitiveOrder());
        out.set("privateKeyHeader", privateKeyHeader());
        out.set("tokenWhitespace", tokenWhitespace());
        RustReference.expect("targets/rules.json", out, TargetRulesReferenceSetTest.class);
    }

    /** {@code value} or {@code refused}, whichever the call gave. */
    private static ObjectNode outcome(Supplier<Object> call) {
        ObjectNode node = RustReference.object();
        try {
            Object value = call.get();
            if (value == null) {
                node.putNull("value");
            } else if (value instanceof Boolean flag) {
                node.put("value", flag);
            } else if (value instanceof Number number) {
                node.put("value", number.longValue());
            } else {
                node.put("value", value.toString());
            }
        } catch (IllegalArgumentException refused) {
            node.put("refused", refused.getMessage());
        }
        return node;
    }

    private static ArrayNode boundedText() {
        ArrayNode cases = RustReference.object().arrayNode();
        List<String> inputs = Arrays.asList(null, "", "   ", " a ", "abcde", "abcdef", " abcde ", GRIN + GRIN,
                GRIN + GRIN + "a", "ab" + GRIN, "abc" + GRIN, NBSP + "ab" + NBSP, "\t\n", "a\u0001");
        for (String input : inputs) {
            ObjectNode one = cases.addObject();
            one.put("input", input);
            one.set("required", outcome(() -> BoundedText.required(input, 5, "A name")));
            one.set("optional", outcome(() -> BoundedText.optional(input, 5, "The description")));
            one.set("within", outcome(() -> BoundedText.within(input, 5, "The URL")));
        }
        return cases;
    }

    private static final List<String> URLS = List.of(
            "https://gitlab.example.org/team/api.git",
            "https://GitLab.Example.Org/Team/API.git/",
            "https://user:token@gitlab.example.org/team/api",
            "https://token@gitlab.example.org/project",
            "https://gitlab.example.org:8443//team//api.git",
            "https://gitlab.example.org./team/api",
            "ssh://git@gitlab.example.org:2222/team/api",
            "ssh://git:secret@gitlab.example.org/team/api",
            "SSH://git@gitlab.example.org/team/api",
            "git@GitLab.example.org:Team/API.git",
            "git@gitlab.example.org:team/sub/group/project.git",
            "git://gitlab.example.org/team/api.git//",
            "https://gitlab.example.org",
            "https://gitlab.example.org/",
            "https://gitlab.example.org/.git",
            "https://gitlab.example.org/a.git.git",
            "file:///srv/repo.git",
            "not a url",
            "https://bad host/x",
            "https://[::1]/team/api",
            "https://gitlab.example.org/team/%41pi",
            "",
            "   ",
            "project");

    private static ArrayNode repositoryUrl() {
        ArrayNode cases = RustReference.object().arrayNode();
        for (String url : URLS) {
            ObjectNode one = cases.addObject();
            one.put("url", url);
            one.put("identity", RepositoryUrl.identity(url).orElse(null));
            one.put("carriesCredential", RepositoryUrl.carriesCredential(url));
            one.put("shortName", RepositoryUrl.shortName(url));
            one.put("displayNameUnnamed", RepositoryUrl.displayName(null, url));
            one.put("displayNameBlank", RepositoryUrl.displayName("  ", url));
            one.put("displayNameNamed", RepositoryUrl.displayName("  The API ", url));
            one.put("displayNameNbsp", RepositoryUrl.displayName(NBSP + "x" + NBSP, url));
        }
        return cases;
    }

    private static ArrayNode maskedForm() {
        ArrayNode cases = RustReference.object().arrayNode();
        String[][] pairs = {
            {"https://***@gitlab.example.org/team/api", "https://user:token@gitlab.example.org/team/api"},
            {"https://user:token@gitlab.example.org/team/api", "https://user:token@gitlab.example.org/team/api"},
            {"https://gitlab.example.org/team/api", "https://gitlab.example.org/team/api"},
            {"https://***@gitlab.example.org/team/api", "https://gitlab.example.org/team/api"},
            {"ssh://git@gitlab.example.org/team/api", "ssh://git@gitlab.example.org/team/api"},
            {"ssh://***@gitlab.example.org/team/api", "ssh://git:pw@gitlab.example.org/team/api"},
            {" https://***@gitlab.example.org/team/api", "https://user:token@gitlab.example.org/team/api"},
        };
        for (String[] pair : pairs) {
            ObjectNode one = cases.addObject();
            one.put("submitted", pair[0]);
            one.put("stored", pair[1]);
            one.put("masked", RepositoryUrl.isMaskedFormOf(pair[0], pair[1]));
        }
        return cases;
    }

    private static ArrayNode repositoryIdentity() {
        ArrayNode cases = RustReference.object().arrayNode();
        String[][] inputs = {
            {"https://gitlab.example.org/team/api.git", null, null},
            {"git@gitlab.example.org:Team/API", "main", ""},
            {"https://gitlab.example.org/team/api", "  develop ", " services/api/// "},
            {"https://gitlab.example.org/team/api", "", "/"},
            {"https://gitlab.example.org/team/api", " ", "a/b"},
            {"not a url", "main", null},
            {"https://gitlab.example.org/team/api", "feature/" + GRIN, NBSP + "x"},
        };
        for (String[] input : inputs) {
            ObjectNode one = cases.addObject();
            one.put("url", input[0]);
            one.put("branch", input[1]);
            one.put("subPath", input[2]);
            Optional<RepositoryIdentity> identity = RepositoryIdentity.of(input[0], input[1], input[2]);
            if (identity.isEmpty()) {
                one.putNull("identity");
            } else {
                ObjectNode found = one.putObject("identity");
                found.put("repository", identity.get().repository());
                found.put("branch", identity.get().branch());
                found.put("subPath", identity.get().subPath());
                found.put("guard", identity.get().guard());
            }
        }
        return cases;
    }

    private static ArrayNode imageReference() {
        ArrayNode cases = RustReference.object().arrayNode();
        String[][] inputs = {
            {null, "nginx", "latest"},
            {"", "library/nginx", "1.27"},
            {"registry.example.org:5000", "team/api", "v1.2.3"},
            {"registry.example.org", "team/api", "sha256:" + "a".repeat(64)},
            {"registry.example.org", "team/api", "sha256:" + "A".repeat(64)},
            {"-bad", "nginx", "latest"},
            {"registry.example.org:999999", "nginx", "latest"},
            {null, "", "latest"},
            {null, null, "latest"},
            {null, "Nginx", "latest"},
            {null, "nginx", ""},
            {null, "nginx", null},
            {null, "nginx", ".bad"},
            {null, "nginx", "a".repeat(129)},
            {null, "a__b", "latest"},
            {null, "a/b/c", "x_y"},
        };
        for (String[] input : inputs) {
            ObjectNode one = cases.addObject();
            one.put("registry", input[0]);
            one.put("imageName", input[1]);
            one.put("tag", input[2]);
            ImageReference reference = new ImageReference(input[0], input[1], input[2]);
            one.put("validate", reference.validate().orElse(null));
            if (input[2] != null) {
                one.put("format", reference.format());
            }
            one.put("displayName", reference.displayName());
        }
        return cases;
    }

    private static ArrayNode assetTier() {
        ArrayNode cases = RustReference.object().arrayNode();
        for (String input : Arrays.asList(null, "", "  ", "tier_1_mission_critical", " TIER_3_INTERNAL ",
                "TIER_2_BUSINESS_OPERATIONAL", "tier 1", "gold", "tıer_1_mıssıon_crıtıcal")) {
            ObjectNode one = cases.addObject();
            one.put("input", input);
            one.set("fromInput", outcome(() -> AssetTier.fromInput(input).name()));
            one.put("fromString", AssetTier.fromString(input).name());
        }
        return cases;
    }

    private static ArrayNode requiredLabel() {
        ArrayNode cases = RustReference.object().arrayNode();
        for (String input : Arrays.asList(null, "", " , ", "Production", " GPU ", "a,b", "a,,", ",x,",
                "x".repeat(256), NBSP + "y", "İstanbul")) {
            ObjectNode one = cases.addObject();
            one.put("input", input);
            one.put("normalizeRequirement", AgentLabels.normalizeRequirement(input).orElse(null));
            one.set("requiredLabel", outcome(() -> RepositoryAdministrationService.requiredLabel(input)));
        }
        return cases;
    }

    private static ArrayNode listWindow() {
        ArrayNode cases = RustReference.object().arrayNode();
        Integer[][] inputs = {
            {null, null}, {null, 0}, {1, null}, {0, null}, {501, null}, {500, 0}, {5, 5}, {5, 3}, {5, -5}, {5, 10},
            {5, 15}, {3, 9}, {-1, null},
        };
        List<Integer> rows = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            rows.add(i);
        }
        for (Integer[] input : inputs) {
            ObjectNode one = cases.addObject();
            one.put("limit", input[0]);
            one.put("offset", input[1]);
            try {
                Optional<ListWindow> window = ListWindow.requested(input[0], input[1]);
                if (window.isEmpty()) {
                    one.putNull("page");
                } else {
                    ArrayNode page = one.putArray("page");
                    window.get().of(rows).forEach(page::add);
                }
            } catch (IllegalArgumentException refused) {
                one.put("refused", refused.getMessage());
            }
        }
        return cases;
    }

    private static ArrayNode gitHostAllowlist() {
        ArrayNode cases = RustReference.object().arrayNode();
        String[] configured = {
            "", "gitlab.example.org", " GitLab.Example.Org. , *.Corp.Example ,, gitlab.example.org",
            "https://gitlab.example.org", "169.254.169.254", "*.", "bad_host",
        };
        List<String> urls = List.of(
                "https://gitlab.example.org/team/api", "git@gitlab.example.org:team/api",
                "https://git.corp.example/team/api", "https://corp.example/team/api",
                "https://evil.example/team/api", "not a url", "https://GITLAB.EXAMPLE.ORG./x");
        for (String entry : configured) {
            ObjectNode one = cases.addObject();
            one.put("configured", entry);
            try {
                GitHostAllowlist list = GitHostAllowlist.parse(entry);
                ArrayNode entries = one.putArray("entries");
                list.entries().forEach(entries::add);
                ArrayNode checks = one.putArray("checks");
                for (String url : urls) {
                    ObjectNode check = checks.addObject();
                    check.put("url", url);
                    check.put("permits", list.permits(url));
                    check.put("refusal", list.refusal(url));
                }
            } catch (IllegalArgumentException refused) {
                one.put("refused", refused.getMessage());
            }
        }
        return cases;
    }

    private static ArrayNode scheduleChoice() {
        ArrayNode cases = RustReference.object().arrayNode();
        Object[][] rows = {
            {false, null, null},
            {true, null, null},
            {false, 60, null},
            {false, null, "0 2 * * *"},
            {false, 30, "0 3 * * *"},
        };
        Object[][] requests = {
            {null, null, null},
            {true, null, null},
            {false, null, null},
            {null, 0, null},
            {null, 15, null},
            {null, -1, null},
            {null, null, ""},
            {null, null, "  0 4 * * *  "},
            {null, null, "not cron"},
            {true, 10, null},
            {true, 0, null},
            {true, null, "0 2 * * *"},
            {true, null, ""},
            {false, 10, "0 2 * * *"},
            {null, 0, ""},
        };
        for (Object[] row : rows) {
            for (Object[] request : requests) {
                ObjectNode one = cases.addObject();
                one.put("manualOnly", (Boolean) row[0]);
                one.put("intervalMinutes", (Integer) row[1]);
                one.put("cron", (String) row[2]);
                one.put("askManualOnly", (Boolean) request[0]);
                one.put("askIntervalMinutes", (Integer) request[1]);
                one.put("askCron", (String) request[2]);
                try {
                    ScheduleChoice result = new ScheduleChoice((Boolean) row[0], (Integer) row[1], (String) row[2])
                            .apply((Boolean) request[0], (Integer) request[1], (String) request[2]);
                    ObjectNode got = one.putObject("result");
                    got.put("manualOnly", result.manualOnly());
                    got.put("intervalMinutes", result.intervalMinutes());
                    got.put("cron", result.cron());
                } catch (IllegalArgumentException refused) {
                    one.put("refused", refused.getMessage());
                }
            }
        }
        return cases;
    }

    private static ArrayNode validatedCron() {
        ArrayNode cases = RustReference.object().arrayNode();
        for (String input : Arrays.asList("", "   ", "0 2 * * *", " 0  2 * * * ", "0 0 2 * * *", "0 2 * *",
                "not a cron", "99 99 * * *", NBSP + "0 2 * * *", "@daily")) {
            ObjectNode one = cases.addObject();
            one.put("input", input);
            one.set("validated", outcome(() -> RepositoryAdministrationService.validatedCron(input)));
        }
        return cases;
    }

    private static ArrayNode inForce() {
        ArrayNode cases = RustReference.object().arrayNode();
        Object[][] inputs = {
            {true, null, null, 7},
            {true, "0 2 * * *", 60, 7},
            {false, "0 2 * * *", 60, 7},
            {false, "not cron", null, 7},
            {false, "  ", 60, 7},
            {false, null, 60, 7},
            {false, null, 0, 7},
            {false, null, null, 7},
            {false, null, null, 0},
            {false, null, -5, 3},
        };
        for (Object[] input : inputs) {
            ObjectNode one = cases.addObject();
            one.put("manualOnly", (Boolean) input[0]);
            one.put("cron", (String) input[1]);
            one.put("intervalMinutes", (Integer) input[2]);
            one.put("defaultDays", (Integer) input[3]);
            RepositoryView view = new RepositoryView(1L, "https://gitlab.example.org/a/b", "main", null, null,
                    (Integer) input[2], (String) input[1], (Boolean) input[0], null, null, null, null,
                    "TIER_2_BUSINESS_OPERATIONAL", false, null);
            Schedules.InForce inForce = TargetSchedules.inForce(view, Duration.ofDays((Integer) input[3]));
            one.put("mode", inForce.mode().wireName());
            one.put("minutes", inForce.interval().map(Duration::toMinutes).orElse(null));
        }
        return cases;
    }

    private static ArrayNode caseInsensitiveOrder() {
        ArrayNode cases = RustReference.object().arrayNode();
        List<String> names = List.of("api", "API", "Api2", "api-2", "ápi", "Zeta", "zeta", "_x", "ß", "SS", "ı", "I",
                "i", "İ", GRIN, "￿", "", "a b", "Ǆ", "ǅ", "ǆ");
        for (String left : names) {
            for (String right : names) {
                ObjectNode one = cases.addObject();
                one.put("left", left);
                one.put("right", right);
                one.put("sign", Integer.signum(String.CASE_INSENSITIVE_ORDER.compare(left, right)));
            }
        }
        return cases;
    }

    private static final Pattern PRIVATE_KEY_HEADER = Pattern.compile("^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----");

    private static ArrayNode privateKeyHeader() {
        ArrayNode cases = RustReference.object().arrayNode();
        for (String input : List.of("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN rsa PRIVATE KEY-----", " -----BEGIN PRIVATE KEY-----",
                "x\n-----BEGIN PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", "-----BEGIN EC2 PRIVATE KEY-----")) {
            ObjectNode one = cases.addObject();
            one.put("input", input);
            one.put("matches", PRIVATE_KEY_HEADER.matcher(input).find());
        }
        return cases;
    }

    private static ArrayNode tokenWhitespace() {
        ArrayNode cases = RustReference.object().arrayNode();
        for (String input : List.of("glpat-abc", "glpat abc", "glpat\tabc", "a" + NBSP + "b", "a b", "a b",
                "a\u001cb", "a\u0085b", "a​b", "a　b")) {
            ObjectNode one = cases.addObject();
            one.put("input", input);
            one.put("whitespace", input.chars().anyMatch(Character::isWhitespace));
        }
        return cases;
    }
}

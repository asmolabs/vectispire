package com.asmolabs.vectispire.common.domain.users;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Accounts and passwords, both ways across the two implementations (see {@code ReferenceSet}): the control plane's
 * Rust port (task 1.1) is held to what this side answers.
 *
 * <p><b>Hashes in both directions.</b> {@code accounts/java-hashes.json} holds hashes {@link PasswordHasher} made —
 * random salts, so they are made once, in write mode, and from then on this test recomputes what each answers and
 * requires the file to say exactly it; the Rust tests verify every one. {@code accounts/rust-hashes.json} is written
 * by the Rust side, and every hash in it must verify here. A hash written by either program is then a credential for
 * both, which is what an account needs to survive the switch.
 *
 * <p><b>The edges, with what Java does.</b> {@code accounts/verify.json} is {@code verify} over malformed and odd
 * encodings derived from the first Java hash — including the ones BouncyCastle throws on, recorded as such — and
 * {@code accounts/rules.json} is every decision and message of {@link AccountRules}, {@link Role#of} and the
 * trimming and bounding the account service applies.
 *
 * <p>Every candidate below is invented, and none is a password anybody uses.
 */
// Ordered: in write mode the edges are derived from the hashes the first test has just written.
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AccountsReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** Invented passphrases, of the shapes a password takes: ASCII, accents, scripts, emoji, long, blank inside. */
    static final List<String> CANDIDATES = List.of(
            "an invented passphrase",
            "Invented-Passphrase-2026!",
            "",
            " leading and trailing ",
            "accentué et café crème",
            "日本語のパスフレーズです",
            "emoji 🙂🙂🙂🙂🙂🙂 inside",
            "x".repeat(200),
            "tab\tand\nnewline inside it");

    private static String write(JsonNode node) throws Exception {
        return JSON.writeValueAsString(node) + "\n";
    }

    @Test
    @Order(1)
    void javaHashesVerifyUnderTheirOwnParameters() throws Exception {
        ArrayNode entries = JSON.createArrayNode();
        if (Boolean.getBoolean("vectispire.rust.reference.write")) {
            for (String candidate : CANDIDATES) {
                ObjectNode entry = entries.addObject();
                entry.put("candidate", candidate);
                entry.put("phc", PasswordHasher.hash(candidate));
            }
            // Past costs: what a deployment from before a raise holds, and what the next sign-in rewrites.
            ObjectNode weaker = entries.addObject();
            weaker.put("candidate", CANDIDATES.get(0));
            weaker.put("phc", PasswordHasher.hash(CANDIDATES.get(0), 4096, 1, 1));
            ObjectNode lanes = entries.addObject();
            lanes.put("candidate", CANDIDATES.get(1));
            lanes.put("phc", PasswordHasher.hash(CANDIDATES.get(1), 19 * 1024, 2, 4));
        } else {
            for (JsonNode committed : JSON.readTree(ReferenceSet.read("accounts/java-hashes.json"))) {
                ObjectNode entry = entries.addObject();
                entry.put("candidate", committed.get("candidate").asText());
                entry.put("phc", committed.get("phc").asText());
            }
        }
        for (JsonNode node : entries) {
            ObjectNode entry = (ObjectNode) node;
            String candidate = entry.get("candidate").asText();
            String phc = entry.get("phc").asText();
            entry.put("verifies", PasswordHasher.verify(candidate, phc));
            entry.put("verifiesOther", PasswordHasher.verify(candidate + "?", phc));
            entry.put("needsRehash", PasswordHasher.needsRehash(phc));
        }
        ReferenceSet.expect("accounts/java-hashes.json", write(entries));
    }

    @Test
    @Order(4)
    void rustHashesVerifyHere() throws Exception {
        var file = ReferenceSet.resolve("accounts/rust-hashes.json");
        assertThat(file).as("written by the Rust side (crates/cp-access/tests/passwords.rs)").exists();
        JsonNode entries = JSON.readTree(Files.readString(file));
        assertThat(entries.size()).isGreaterThanOrEqualTo(CANDIDATES.size());
        for (JsonNode entry : entries) {
            String candidate = entry.get("candidate").asText();
            String phc = entry.get("phc").asText();
            assertThat(PasswordHasher.verify(candidate, phc)).as("Rust's hash of %s", candidate).isTrue();
            assertThat(PasswordHasher.verify(candidate + "?", phc)).isFalse();
            assertThat(PasswordHasher.needsRehash(phc)).isEqualTo(entry.get("needsRehash").asBoolean());
        }
    }

    /** {@code verify} over encodings derived from a real one, and what Java answers — or throws. */
    @Test
    @Order(2)
    void verifyOnTheEdges() throws Exception {
        JsonNode first = JSON.readTree(ReferenceSet.read("accounts/java-hashes.json")).get(0);
        String candidate = first.get("candidate").asText();
        String phc = first.get("phc").asText();
        String[] parts = phc.split("\\$");
        String salt = parts[4];
        String digest = parts[5];
        String head = "$argon2id$v=19$";

        List<String[]> cases = new ArrayList<>();
        cases.add(new String[] {"the hash itself", candidate, phc});
        cases.add(new String[] {"null password", null, phc});
        cases.add(new String[] {"null hash", candidate, null});
        cases.add(new String[] {"empty hash", candidate, ""});
        cases.add(new String[] {"blank hash", candidate, " \t\n"});
        cases.add(new String[] {"one trailing dollar", candidate, phc + "$"});
        cases.add(new String[] {"three trailing dollars", candidate, phc + "$$$"});
        cases.add(new String[] {"an extra part", candidate, phc + "$extra"});
        cases.add(new String[] {"no leading dollar", candidate, phc.substring(1)});
        cases.add(new String[] {"argon2i", candidate, phc.replace("$argon2id$", "$argon2i$")});
        cases.add(new String[] {"upper-case algorithm", candidate, phc.replace("$argon2id$", "$ARGON2ID$")});
        cases.add(new String[] {"version 16, not read", candidate, phc.replace("$v=19$", "$v=16$")});
        cases.add(new String[] {"no version", candidate, phc.replace("$v=19$", "$$")});
        cases.add(new String[] {"parameters reordered", candidate, head + "t=2,p=1,m=19456$" + salt + "$" + digest});
        cases.add(new String[] {"plus sign", candidate, head + "m=+19456,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"leading zeros", candidate, head + "m=019456,t=02,p=01$" + salt + "$" + digest});
        cases.add(new String[] {"a parameter twice, first wins", candidate, head + "m=19456,m=1,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"missing t", candidate, head + "m=19456,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"t not a number", candidate, head + "m=19456,t=two,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"m overflows int", candidate, head + "m=2147483648,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"a space before m", candidate, head + " m=19456,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"t zero", candidate, head + "m=19456,t=0,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"p zero", candidate, head + "m=19456,t=2,p=0$" + salt + "$" + digest});
        cases.add(new String[] {"m below 8 lanes", candidate, head + "m=4,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"m negative", candidate, head + "m=-1,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"another memory cost", candidate, head + "m=19457,t=2,p=1$" + salt + "$" + digest});
        cases.add(new String[] {"salt padded", candidate, head + "m=19456,t=2,p=1$" + salt + "==$" + digest});
        cases.add(new String[] {"digest padded", candidate, head + "m=19456,t=2,p=1$" + salt + "$" + digest + "="});
        cases.add(new String[] {"url-safe alphabet", candidate, phc.replace('+', '-').replace('/', '_')});
        cases.add(new String[] {"salt with a space", candidate, head + "m=19456,t=2,p=1$" + salt.substring(0, 4) + " " + salt.substring(4) + "$" + digest});
        cases.add(new String[] {"salt one character short", candidate, head + "m=19456,t=2,p=1$" + salt.substring(1) + "$" + digest});
        cases.add(new String[] {"salt cut to 8 characters", candidate, head + "m=19456,t=2,p=1$" + salt.substring(0, 8) + "$" + digest});
        cases.add(new String[] {"digest cut to 16 bytes", candidate, head + "m=19456,t=2,p=1$" + salt + "$" + digest.substring(0, 22)});
        cases.add(new String[] {"empty salt", candidate, head + "m=19456,t=2,p=1$$" + digest});
        cases.add(new String[] {"empty password against its hash", "", phc});

        ArrayNode entries = JSON.createArrayNode();
        for (String[] c : cases) {
            ObjectNode entry = entries.addObject();
            entry.put("case", c[0]);
            entry.put("candidate", c[1]);
            entry.put("phc", c[2]);
            String outcome;
            try {
                outcome = String.valueOf(PasswordHasher.verify(c[1], c[2]));
            } catch (RuntimeException thrown) {
                outcome = "throws " + thrown.getClass().getSimpleName();
            }
            entry.put("verify", outcome);
            entry.put("needsRehash", PasswordHasher.needsRehash(c[2]));
        }
        ReferenceSet.expect("accounts/verify.json", write(entries));
    }

    @Test
    @Order(3)
    void theRulesAndTheirMessages() throws Exception {
        ObjectNode root = JSON.createObjectNode();

        List<String> names = new ArrayList<>(List.of(
                "alice", "a", "ab", "a".repeat(64), "a".repeat(65), "alice.smith-2_x", "ali ce", "ali­ce",
                "Alice", "àlice", "alice\n", "", " alice ", "al​ice", "a$b", "..", "--", "__", " alice"));
        ArrayNode usernames = root.putArray("usernames");
        for (String name : names) {
            ObjectNode entry = usernames.addObject();
            entry.put("name", name);
            entry.put("wellFormed", AccountRules.isWellFormedUsername(name));
            entry.put("refusal", AccountRules.validateUsername(name).orElse(null));
        }
        ObjectNode nullName = usernames.addObject();
        nullName.putNull("name");
        nullName.put("wellFormed", AccountRules.isWellFormedUsername(null));
        nullName.put("refusal", AccountRules.validateUsername(null).orElse(null));

        List<String> passwords = new ArrayList<>(CANDIDATES);
        passwords.addAll(List.of("x".repeat(11), "x".repeat(12), "🙂".repeat(5), "🙂".repeat(6), "é".repeat(11), " ".repeat(12)));
        ArrayNode passwordRules = root.putArray("passwords");
        for (String password : passwords) {
            ObjectNode entry = passwordRules.addObject();
            entry.put("candidate", password);
            entry.put("refusal", AccountRules.validatePassword(password).orElse(null));
        }
        ObjectNode nullPassword = passwordRules.addObject();
        nullPassword.putNull("candidate");
        nullPassword.put("refusal", AccountRules.validatePassword(null).orElse(null));

        // What the account service does to a typed username, role, e-mail and display name before the rules.
        List<String> texts = List.of(
                "  alice  ", "\talice\n", " alice ", " alice", "\u0000alice\u001F", "", "   ",
                "admin", "Security_Champion", "straße", "ciso ", "ﬁ", "userİ");
        ArrayNode trimmed = root.putArray("texts");
        for (String text : texts) {
            ObjectNode entry = trimmed.addObject();
            entry.put("text", text);
            entry.put("trim", text.trim());
            entry.put("upper", text.trim().toUpperCase(Locale.ROOT));
            entry.put("length", text.length());
            Optional<Role> role = Role.of(text.trim().toUpperCase(Locale.ROOT));
            entry.put("role", role.map(Role::name).orElse(null));
            String bounded;
            try {
                bounded = BoundedText.optional(text, 5, "The label");
            } catch (RuntimeException refused) {
                bounded = "refused: " + refused.getMessage();
            }
            entry.put("boundedTo5", bounded);
        }

        ArrayNode roles = root.putArray("roles");
        for (Role role : Role.values()) {
            ObjectNode entry = roles.addObject();
            entry.put("name", role.name());
            entry.put("administrative", role.isAdministrative());
            entry.put("globalSecurityScope", role.hasGlobalSecurityScope());
            entry.put("canApproveTriage", role.canApproveTriage());
            entry.put("canWriteGovernance", role.canWriteGovernance());
            entry.put("canCauseEffects", role.canCauseEffects());
            entry.put("governsPlatform", role.governsPlatform());
        }
        ArrayNode of = root.putArray("roleOf");
        for (String name : List.of("ADMIN", "admin", "Admin", " ADMIN", "SUPERUSER", "", "ROOT", "SECURITY_CHAMPION")) {
            ObjectNode entry = of.addObject();
            entry.put("text", name);
            entry.put("role", Role.of(name).map(Role::name).orElse(null));
        }

        ArrayNode lockout = root.putArray("selfLockout");
        for (int bits = 0; bits < 16; bits++) {
            for (int remaining : new int[] {0, 1}) {
                boolean isSelf = (bits & 1) != 0, wasAdmin = (bits & 2) != 0, willBeAdmin = (bits & 4) != 0, willBeActive = (bits & 8) != 0;
                ObjectNode entry = lockout.addObject();
                entry.put("isSelf", isSelf);
                entry.put("wasAdmin", wasAdmin);
                entry.put("willBeAdmin", willBeAdmin);
                entry.put("willBeActive", willBeActive);
                entry.put("remaining", remaining);
                entry.put("refusal", AccountRules.refuseSelfLockout(
                        new AccountRules.Change(isSelf, wasAdmin, willBeAdmin, willBeActive, remaining)).orElse(null));
            }
        }

        List<Optional<Role>> optional = new ArrayList<>();
        optional.add(Optional.empty());
        for (Role role : Role.values()) {
            optional.add(Optional.of(role));
        }
        ArrayNode governor = root.putArray("governor");
        for (Optional<Role> acting : optional) {
            for (Optional<Role> current : optional) {
                for (Optional<Role> next : optional) {
                    ObjectNode entry = governor.addObject();
                    entry.put("acting", acting.map(Role::name).orElse(null));
                    entry.put("current", current.map(Role::name).orElse(null));
                    entry.put("next", next.map(Role::name).orElse(null));
                    entry.put("refusal", AccountRules.refuseGovernorAdministration(acting, current, next).orElse(null));
                }
            }
        }

        ArrayNode ownRole = root.putArray("ownRoleChange");
        List<String> roleTexts = new ArrayList<>(List.of("ADMIN", "admin", "USER", "Ciso", "CISO", "straße", "STRASSE", "ǅ", "ǆ", "ΣΑΣ", "σας"));
        roleTexts.add(null);
        for (boolean isSelf : new boolean[] {false, true}) {
            for (String current : roleTexts) {
                for (String next : roleTexts) {
                    ObjectNode entry = ownRole.addObject();
                    entry.put("isSelf", isSelf);
                    entry.put("current", current);
                    entry.put("next", next);
                    String refusal;
                    try {
                        refusal = AccountRules.refuseOwnRoleChange(isSelf, current, next).orElse(null);
                    } catch (RuntimeException thrown) {
                        refusal = "throws " + thrown.getClass().getSimpleName();
                    }
                    entry.put("refusal", refusal);
                }
            }
        }

        ArrayNode deletion = root.putArray("deletion");
        for (boolean isSelf : new boolean[] {false, true}) {
            for (boolean isAdmin : new boolean[] {false, true}) {
                for (int remaining : new int[] {0, 1, 2}) {
                    ObjectNode entry = deletion.addObject();
                    entry.put("isSelf", isSelf);
                    entry.put("isAdmin", isAdmin);
                    entry.put("remaining", remaining);
                    entry.put("refusal", AccountRules.refuseDeletion(isSelf, isAdmin, remaining).orElse(null));
                }
            }
        }

        ReferenceSet.expect("accounts/rules.json", write(root));
    }
}

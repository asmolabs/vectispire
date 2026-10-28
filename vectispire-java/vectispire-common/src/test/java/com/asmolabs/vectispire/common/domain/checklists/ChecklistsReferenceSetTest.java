package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Component;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.CoverageReport;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Imported;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.IssueCount;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Kept;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.NotKept;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.NotRead;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PackageCounts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Packages;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginRun;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginRuns;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.PluginState;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewRead;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewUnlinked;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ReviewUnreadable;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ScanLanguages;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Scanned;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.ScopeFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Source;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Suite;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.TestReport;
import com.asmolabs.vectispire.common.domain.dependencies.MavenVersion;
import com.asmolabs.vectispire.common.domain.dependencies.MavenVersionRange;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * What the checklists domain answers for {@code checklists/inputs.json} — the answers the Rust port
 * ({@code vectispire_cp_checklists}, and the facts and Maven versions in {@code vectispire_domain}) is held to.
 *
 * <p>Most of it is a data contract: the normalised text and the item key a version pairs by, the content digest
 * that decides whether an answer carried onto a line waits for a confirmation, the rule's canonical form whose
 * SHA-256 a measurement names, the evidence a sign-off freezes and its digest. The rest is what a person reads:
 * every refusal's sentence, the measurement's summary and evidence, the reminder's mail. The inputs sit where a
 * port drifts — NFKC and Java's whitespace classes, UTF-16 lengths and order, decimals written two ways, Maven's
 * order with its qualifiers and Unicode digits, an instant to the nanosecond, a threshold met exactly.
 *
 * <p>An answer is the value, or {@code {"refused": message}} for an {@link InvalidInputException} — the words a
 * caller reads — or {@code {"illegal": message}} for the {@link IllegalArgumentException} or {@link
 * IllegalStateException} a defect raises.
 */
class ChecklistsReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final ObjectMapper PLAIN = new ObjectMapper();

    @Test
    void theAnswersTheRustChecklistsDomainIsHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("checklists/inputs.json"));
        ObjectNode answers = JSON.createObjectNode();

        vocabulary(answers.putObject("vocabulary"));

        ArrayNode texts = answers.putArray("texts");
        inputs.path("texts").forEach(text -> texts.add(ChecklistText.normalize(text(text))));

        ArrayNode ids = answers.putArray("itemIds");
        inputs.path("itemIds").forEach(id -> ids.add(answer(() -> PLAIN.valueToTree(ItemKey.fromId(text(id)).value()))));
        ArrayNode controls = answers.putArray("controls");
        inputs.path("controls").forEach(control ->
                controls.add(answer(() -> PLAIN.valueToTree(ItemKey.fromControl(text(control)).value()))));

        ArrayNode parsed = answers.putArray("answers");
        inputs.path("answers").forEach(value -> parsed.add(answer(() -> {
            ChecklistAnswer answer = ChecklistAnswer.parse(text(value));
            return PLAIN.createObjectNode().put("wire", answer.wireName()).put("requiresComment", answer.requiresComment());
        })));
        ArrayNode authors = answers.putArray("authors");
        inputs.path("authors").forEach(value -> authors.addObject()
                .put("isSystem", AnswerAuthor.isSystem(text(value)))
                .put("stored", AnswerAuthor.ofStored(text(value)).map(AnswerAuthor::wireName).orElse(null)));

        ArrayNode words = answers.putArray("answerWords");
        for (JsonNode input : inputs.path("answerWords")) {
            words.add(answer(() -> {
                AnswerWords mapped = new AnswerWords(text(input.path("yes")), text(input.path("no")),
                        Optional.ofNullable(text(input.path("notApplicable"))));
                ObjectNode node = PLAIN.createObjectNode().put("offersNotApplicable", mapped.offersNotApplicable());
                ArrayNode read = node.putArray("answerOf");
                input.path("words").forEach(word ->
                        read.add(mapped.answerOf(text(word)).map(ChecklistAnswer::wireName).orElse(null)));
                ArrayNode word = node.putArray("word");
                ArrayNode written = node.putArray("written");
                for (ChecklistAnswer each : ChecklistAnswer.values()) {
                    word.add(answer(() -> PLAIN.valueToTree(mapped.word(each))));
                    written.add(mapped.written(each));
                }
                return node;
            }));
        }
        ArrayNode given = answers.putArray("givenAnswers");
        for (JsonNode input : inputs.path("givenAnswers")) {
            given.add(answer(() -> {
                AnswerWords offered = new AnswerWords("Oui", "Non", input.path("offersNotApplicable").asBoolean()
                        ? Optional.of("Sans objet") : Optional.empty());
                GivenAnswer answer = GivenAnswer.of(ChecklistAnswer.parse(text(input.path("value"))),
                        text(input.path("comment")), offered);
                return PLAIN.createObjectNode().put("value", answer.value().wireName())
                        .put("comment", answer.comment().orElse(null));
            }));
        }

        ArrayNode evidence = answers.putArray("evidence");
        inputs.path("evidence").forEach(input -> evidence.add(answer(() ->
                PLAIN.valueToTree(requirement(input).canonical()))));

        ArrayNode items = answers.putArray("items");
        inputs.path("items").forEach(input -> items.add(answer(() -> {
            ChecklistItem item = item(input);
            return PLAIN.createObjectNode().put("key", item.key().value()).put("domain", item.domain())
                    .put("objective", item.objective()).put("control", item.control()).put("contact", item.contact())
                    .put("kpi", item.kpi()).put("contentDigest", item.contentDigest());
        })));

        ArrayNode pairings = answers.putArray("pairings");
        inputs.path("pairings").forEach(input -> pairings.add(answer(() -> pairing(input))));

        ArrayNode contacts = answers.putArray("contacts");
        List<String> cells = new ArrayList<>();
        for (JsonNode input : inputs.path("contacts")) {
            String cell = text(input);
            if (cell != null) {
                cells.add(cell);
            }
            ObjectNode node = contacts.addObject();
            profiles(node.putArray("profiles"), ContactProfiles.of(cell));
            ArrayNode keys = node.putArray("keys");
            if (cell != null) {
                ContactProfiles.keysOf(cell).forEach(keys::add);
            }
        }
        profiles(answers.putArray("allContacts"), ContactProfiles.of(cells));
        ArrayNode contactKeys = answers.putArray("contactKeys");
        inputs.path("contactKeys").forEach(input -> contactKeys.add(answer(() ->
                PLAIN.valueToTree(ContactProfiles.keyOf(text(input))))));

        reminders(inputs.path("reminders"), answers.putObject("reminders"));

        ArrayNode scopes = answers.putArray("scopes");
        inputs.path("scopes").forEach(input -> scopes.add(answer(() -> {
            ToolScope scope = ToolScope.parse(text(input));
            return PLAIN.createObjectNode().put("key", scope.key()).put("kind", scope.getClass().getSimpleName());
        })));

        ArrayNode coverageScopes = answers.putArray("coverageScopes");
        inputs.path("coverageScopes").forEach(input -> coverageScopes.add(answer(() -> {
            CoverageScope scope = new CoverageScope(strings(input.path("include")), strings(input.path("exclude")));
            ObjectNode node = PLAIN.createObjectNode();
            scope.include().forEach(node.putArray("include")::add);
            scope.exclude().forEach(node.putArray("exclude")::add);
            node.put("describe", scope.describe());
            ArrayNode matches = node.putArray("matches");
            input.path("paths").forEach(path -> matches.add(scope.matches(path.asText())));
            return node;
        })));

        ArrayNode suites = answers.putArray("suites");
        for (JsonNode input : inputs.path("suites")) {
            SuitePattern pattern = SuitePattern.of(input.path("pattern").asText());
            ArrayNode matches = suites.addArray();
            input.path("names").forEach(name -> matches.add(pattern.matches(text(name))));
        }

        ArrayNode versions = answers.putArray("versions");
        for (JsonNode pair : inputs.path("versions")) {
            versions.add(Integer.signum(MavenVersion.of(pair.get(0).asText()).compareTo(MavenVersion.of(pair.get(1).asText()))));
        }
        ArrayNode ranges = answers.putArray("ranges");
        for (JsonNode input : inputs.path("ranges")) {
            String spec = text(input.path("spec"));
            ObjectNode node = ranges.addObject()
                    .put("looksLikeRange", MavenVersionRange.looksLikeRange(spec))
                    .put("readable", MavenVersionRange.read(spec).isPresent());
            node.set("parsed", answer(() -> {
                MavenVersionRange range = MavenVersionRange.parse(spec);
                ObjectNode read = PLAIN.createObjectNode().put("written", range.toString());
                ArrayNode contains = read.putArray("contains");
                input.path("versions").forEach(version -> contains.add(range.contains(version.asText())));
                return read;
            }));
        }

        ArrayNode rules = answers.putArray("rules");
        inputs.path("rules").forEach(input -> rules.add(answer(() -> rule(ChecklistRule.parse(input.asText())))));
        ArrayNode stored = answers.putArray("storedRules");
        inputs.path("storedRules").forEach(input -> stored.add(answer(() ->
                rule(ChecklistRule.fromCanonical(input.asText())))));

        ArrayNode evaluations = answers.putArray("evaluations");
        for (JsonNode input : inputs.path("evaluations")) {
            ObjectNode node = evaluations.addObject().put("name", input.path("name").asText());
            node.set("measured", answer(() -> {
                String ruleText = input.path("rule").asText();
                ChecklistRule rule = input.path("stored").asBoolean()
                        ? ChecklistRule.fromCanonical(ruleText) : ChecklistRule.parse(ruleText);
                Measurement measured = RuleEvaluation.evaluate(rule, facts(input.path("facts")),
                        Instant.parse(input.path("now").asText()));
                return PLAIN.createObjectNode().put("evidence", measured.evidenceJson())
                        .put("digest", measured.evidenceDigest())
                        .put("rereads", Measurement.read(measured.evidenceJson()).evidenceJson()
                                .equals(measured.evidenceJson()));
            }));
        }
        ArrayNode measurements = answers.putArray("storedMeasurements");
        inputs.path("storedMeasurements").forEach(input -> measurements.add(answer(() ->
                PLAIN.valueToTree(Measurement.read(input.asText()).evidenceJson()))));
        ArrayNode reviews = answers.putArray("storedReviews");
        inputs.path("storedReviews").forEach(input -> reviews.add(answer(() ->
                PLAIN.valueToTree(ChangeReviewEvidence.read(input.asText()).json()))));

        ArrayNode reconciliations = answers.putArray("reconciliations");
        List<Optional<ChecklistAnswer>> givenAnswers = new ArrayList<>(List.of(Optional.empty()));
        for (ChecklistAnswer each : ChecklistAnswer.values()) {
            givenAnswers.add(Optional.of(each));
        }
        List<Optional<MeasurementOutcome>> outcomes = new ArrayList<>(List.of(Optional.empty()));
        for (MeasurementOutcome each : MeasurementOutcome.values()) {
            outcomes.add(Optional.of(each));
        }
        for (Optional<ChecklistAnswer> answer : givenAnswers) {
            for (Optional<MeasurementOutcome> outcome : outcomes) {
                reconciliations.add(Reconciliation.of(answer, outcome).wireName());
            }
        }

        ReferenceSet.expect("checklists/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    // ------------------------------------------------------------------ the answers' shapes

    private static JsonNode answer(Supplier<JsonNode> computed) {
        try {
            return computed.get();
        } catch (InvalidInputException refused) {
            return PLAIN.createObjectNode().put("refused", refused.getMessage());
        } catch (IllegalArgumentException | IllegalStateException defect) {
            return PLAIN.createObjectNode().put("illegal", defect.getMessage());
        }
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }

    private static List<String> strings(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        List<String> values = new ArrayList<>();
        node.forEach(value -> values.add(text(value)));
        return values;
    }

    private static void vocabulary(ObjectNode node) {
        Map<String, List<String>> lists = new java.util.LinkedHashMap<>();
        lists.put("answers", wire(ChecklistAnswer.values(), ChecklistAnswer::wireName));
        lists.put("authors", wire(AnswerAuthor.values(), AnswerAuthor::wireName));
        lists.put("outcomes", wire(MeasurementOutcome.values(), MeasurementOutcome::wireName));
        lists.put("reasons", wire(NoDataReason.values(), NoDataReason::wireName));
        lists.put("reconciliations", wire(Reconciliation.values(), Reconciliation::wireName));
        lists.put("evidenceKinds", wire(EvidenceRequirement.Kind.values(), EvidenceRequirement.Kind::wireName));
        lists.put("ruleKinds", wire(ChecklistRule.Kind.values(), ChecklistRule.Kind::wireName));
        lists.put("sources", wire(Source.values(), Source::wireName));
        lists.put("gaps", wire(ChecklistReminder.Gap.values(), gap -> gap.wireName() + ": " + gap.words()));
        lists.put("columns", wire(ChecklistColumn.values(), column -> column.wireName() + (column.required() ? "!" : "")));
        lists.put("sourceLanguages", wire(Language.values(),
                language -> language.wireName() + (SourceLanguages.isSource(language) ? "" : " (not source)")));
        lists.put("builtInScopes", ToolScope.BUILT_IN_TYPES.stream().map(type -> new ToolScope.BuiltIn(type).key())
                .sorted().toList());
        lists.forEach((name, values) -> values.forEach(node.putArray(name)::add));
    }

    private static <E> List<String> wire(E[] values, java.util.function.Function<E, String> name) {
        return java.util.Arrays.stream(values).map(name).toList();
    }

    private static ObjectNode rule(ChecklistRule rule) {
        String canonical = rule.canonical();
        return PLAIN.createObjectNode().put("kind", rule.kind().wireName()).put("canonical", canonical)
                .put("digest", rule.digest())
                .put("rereads", ChecklistRule.fromCanonical(canonical).canonical().equals(canonical));
    }

    private static EvidenceRequirement requirement(JsonNode input) {
        EvidenceRequirement.Kind kind = EvidenceRequirement.Kind.parse(text(input.path("kind")));
        JsonNode validity = input.path("validity");
        return new EvidenceRequirement(kind, validity.isNull() || validity.isMissingNode()
                ? Optional.empty() : Optional.of(validity.asInt()));
    }

    private static ItemKey key(JsonNode input) {
        return input.has("id") ? ItemKey.fromId(text(input.path("id"))) : ItemKey.fromControl(text(input.path("control")));
    }

    private static ChecklistItem item(JsonNode input) {
        return new ChecklistItem(key(input.path("key")), input.path("position").asInt(), text(input.path("domain")),
                text(input.path("objective")), text(input.path("control")), text(input.path("contact")),
                text(input.path("kpi")), input.path("row").asInt(), requirement(input.path("evidence")),
                Optional.ofNullable(text(input.path("boundRule"))));
    }

    private static List<ChecklistItem> items(JsonNode input) {
        List<ChecklistItem> items = new ArrayList<>();
        input.forEach(item -> items.add(item(item)));
        return items;
    }

    private static JsonNode pairing(JsonNode input) {
        List<VersionPairing.ManualPair> byHand = new ArrayList<>();
        input.path("byHand").forEach(pair -> byHand.add(new VersionPairing.ManualPair(key(pair.get(0)), key(pair.get(1)))));
        VersionPairing pairing = VersionPairing.of(items(input.path("previous")), items(input.path("next")), byHand);
        ObjectNode node = PLAIN.createObjectNode();
        ArrayNode changes = node.putArray("changes");
        for (VersionPairing.Change change : pairing.changes()) {
            ObjectNode entry = changes.addObject();
            switch (change) {
                case VersionPairing.Unchanged same -> entry.put("change", "unchanged").put("previous", same.previous().row())
                        .put("next", same.next().row()).put("key", same.next().key().value());
                case VersionPairing.Changed changed -> entry.put("change", "changed")
                        .put("previous", changed.previous().row()).put("next", changed.next().row())
                        .put("key", changed.next().key().value()).put("byHand", changed.pairedByHand());
                case VersionPairing.Added added -> entry.put("change", "added").put("next", added.next().row())
                        .put("key", added.next().key().value());
                case VersionPairing.Removed removed -> entry.put("change", "removed")
                        .put("previous", removed.previous().row()).put("key", removed.previous().key().value());
            }
        }
        ArrayNode next = node.putArray("next");
        pairing.next().forEach(item -> next.add(item.key().value()));
        return node;
    }

    private static void profiles(ArrayNode node, List<ContactProfiles.Profile> profiles) {
        profiles.forEach(profile -> node.addArray().add(profile.key()).add(profile.label()));
    }

    private static void reminders(JsonNode input, ObjectNode node) {
        ArrayNode contacts = node.putArray("toContact");
        for (JsonNode reminder : input.path("toContact")) {
            List<ChecklistReminder.ProfileLines> profiles = new ArrayList<>();
            for (JsonNode profile : reminder.path("profiles")) {
                List<ChecklistReminder.Line> lines = new ArrayList<>();
                profile.path("lines").forEach(line ->
                        lines.add(new ChecklistReminder.Line(line.path("position").asInt(), line.path("control").asText())));
                profiles.add(new ChecklistReminder.ProfileLines(profile.path("projectId").asLong(),
                        profile.path("projectName").asText(), profile.path("profile").asText(), lines));
            }
            message(contacts, ChecklistReminder.toContact(Optional.ofNullable(text(reminder.path("name"))), profiles,
                    LocalDate.parse(reminder.path("week").asText()), Optional.ofNullable(text(reminder.path("publicUrl")))));
        }
        ArrayNode cisos = node.putArray("toCiso");
        for (JsonNode reminder : input.path("toCiso")) {
            List<ChecklistReminder.Unreached> unreached = new ArrayList<>();
            reminder.path("unreached").forEach(profile -> unreached.add(new ChecklistReminder.Unreached(
                    profile.path("projectId").asLong(), profile.path("projectName").asText(),
                    profile.path("profile").asText(), profile.path("lines").asInt(),
                    ChecklistReminder.Gap.valueOf(profile.path("gap").asText()))));
            message(cisos, ChecklistReminder.toCiso(unreached, LocalDate.parse(reminder.path("week").asText()),
                    Optional.ofNullable(text(reminder.path("publicUrl")))));
        }
    }

    private static void message(ArrayNode node, ChecklistReminder.Message message) {
        node.addObject().put("subject", message.subject()).put("body", message.body());
    }

    // ------------------------------------------------------------------ the facts, as inputs.json writes them

    private static MeasurementFacts facts(JsonNode input) {
        List<Long> repositories = new ArrayList<>();
        input.path("repositories").forEach(id -> repositories.add(id.asLong()));
        Map<String, Map<Long, ScopeFacts>> scopes = new HashMap<>();
        input.path("scopes").properties().forEach(scope -> scopes.put(scope.getKey(),
                byRepository(scope.getValue(), ChecklistsReferenceSetTest::scopeFacts)));
        Map<String, Map<Long, List<IssueCount>>> counts = new HashMap<>();
        input.path("counts").properties().forEach(scope -> counts.put(scope.getKey(), byRepository(scope.getValue(),
                list -> {
                    List<IssueCount> issues = new ArrayList<>();
                    list.forEach(count -> issues.add(new IssueCount(count.get(0).asText(), count.get(1).asText(),
                            count.get(2).asLong())));
                    return issues;
                })));
        Map<Long, Boolean> scheduled = byRepository(input.path("scheduled"), JsonNode::asBoolean);
        Map<Long, CoverageReport> coverage = byRepository(input.path("coverage"), report -> new CoverageReport(
                look(report.path("look")), report.path("lines").get(0).asLong(), report.path("lines").get(1).asLong(),
                pairPart(report.path("branches"), 0), pairPart(report.path("branches"), 1),
                packages(report.path("packages"))));
        Map<Long, TestReport> tests = byRepository(input.path("tests"), report -> {
            List<Suite> suites = new ArrayList<>();
            report.path("suites").forEach(suite -> suites.add(new Suite(suite.get(0).asText(), suite.get(1).asInt(),
                    suite.get(2).asInt(), suite.get(3).asInt(), suite.get(4).asInt())));
            return new TestReport(look(report.path("look")), suites);
        });
        Map<Long, List<Component>> components = byRepository(input.path("components"), list -> {
            List<Component> listed = new ArrayList<>();
            list.forEach(component -> listed.add(new Component(text(component.get(0)), text(component.get(1)),
                    text(component.get(2)))));
            return listed;
        });
        Map<Long, ScanLanguages> languages = byRepository(input.path("languages"), recorded -> new ScanLanguages(
                languages(recorded.path("detected")), languages(recorded.path("sast"))));
        Map<Long, ReviewFacts> reviews = byRepository(input.path("reviews"), ChecklistsReferenceSetTest::review);
        return new MeasurementFacts(repositories, scopes, counts, scheduled, coverage, tests, components, languages,
                reviews);
    }

    private static <T> Map<Long, T> byRepository(JsonNode node, java.util.function.Function<JsonNode, T> read) {
        Map<Long, T> values = new HashMap<>();
        node.properties().forEach(entry -> values.put(Long.parseLong(entry.getKey()), read.apply(entry.getValue())));
        return values;
    }

    private static Look look(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        Source source = Source.valueOf(node.get(0).asText().toUpperCase(Locale.ROOT));
        return new Look(source, node.get(1).asLong(), Instant.parse(node.get(2).asText()),
                Optional.ofNullable(text(node.get(3))));
    }

    private static ScopeFacts scopeFacts(JsonNode node) {
        if (node.has("scanned")) {
            JsonNode scanned = node.path("scanned");
            return new Scanned(Optional.ofNullable(look(scanned.path("newest"))), scanned.path("sbom").asBoolean(),
                    scanned.path("recorded").asInt(), scanned.path("unrecorded").asInt());
        }
        if (node.has("plugin")) {
            JsonNode plugin = node.path("plugin");
            List<PluginRun> runs = new ArrayList<>();
            plugin.path("runs").forEach(run -> runs.add(new PluginRun(look(run.path("scan")),
                    PluginState.valueOf(run.path("state").asText()), languages(run.path("reads")))));
            return new PluginRuns(runs, plugin.path("scans").asInt(), plugin.path("namedBefore").asBoolean());
        }
        JsonNode imported = node.path("imported");
        return new Imported(Optional.ofNullable(look(imported.path("newest"))), imported.path("unrecorded").asBoolean());
    }

    private static Optional<Set<Language>> languages(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return Optional.empty();
        }
        Set<Language> languages = new java.util.HashSet<>();
        node.forEach(name -> languages.add(Language.fromWireName(name.asText()).orElseThrow()));
        return Optional.of(languages);
    }

    private static Optional<Long> pairPart(JsonNode pair, int index) {
        return pair == null || pair.isNull() || pair.isMissingNode() ? Optional.empty() : Optional.of(pair.get(index).asLong());
    }

    private static Optional<Long> optionalLong(JsonNode node) {
        return node == null || node.isNull() ? Optional.empty() : Optional.of(node.asLong());
    }

    private static Packages packages(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return new NotRead();
        }
        if (node.isTextual()) {
            return new MeasurementFacts.Unrecorded();
        }
        if (node.isObject()) {
            return new NotKept(node.path("notKept").asText());
        }
        List<PackageCounts> packages = new ArrayList<>();
        node.forEach(part -> packages.add(new PackageCounts(part.get(0).asText(), part.get(1).asLong(),
                part.get(2).asLong(), optionalLong(part.get(3)), optionalLong(part.get(4)))));
        return new Kept(packages);
    }

    private static ReviewFacts review(JsonNode node) {
        if (node.has("unlinked")) {
            return new ReviewUnlinked(look(node.path("unlinked").path("look")), node.path("unlinked").path("why").asText());
        }
        if (node.has("unreadable")) {
            return new ReviewUnreadable(look(node.path("unreadable").path("look")),
                    node.path("unreadable").path("why").asText());
        }
        JsonNode read = node.path("read");
        return new ReviewRead(look(read.path("look")), ChangeReviewEvidence.read(read.path("evidence").asText()));
    }
}

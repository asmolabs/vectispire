package com.asmolabs.vectispire.core;

import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.Dependency;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import com.tngtech.archunit.library.dependencies.SliceAssignment;
import com.tngtech.archunit.library.dependencies.SliceIdentifier;
import com.tngtech.archunit.library.dependencies.SliceRule;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.NamedInterface;

/**
 * The layer rule, checked.
 *
 * <p>The module split already carries the part that matters most: {@code vectispire-agent} does
 * not depend on {@code vectispire-core}, so a driver is not on its classpath and the violation
 * fails to compile rather than failing review. What one module cannot express is the rule
 * <em>inside</em> {@code vectispire-core}, and that is what this file is for.
 *
 * <p>It exists because an architecture rule written in a document is not a rule: it is true
 * the day it is written and false six months later. The NestJS tree learned that, and its
 * {@code architecture.spec.ts} is this file's direct ancestor.
 *
 * <h2>One packaging, one set of layers</h2>
 *
 * The control plane is packaged by vertical module (decisions 0028 and 0029): a domain is {@code
 * core.<domain>}, its API at the root, its controllers in {@code web}, its implementation in {@code
 * internal}, its entities and repositories in {@code persistence}. The layers are the same six they
 * were when the packages were the layers — {@code core.api}, {@code core.services}, {@code
 * core.repositories}, {@code core.persistence}, emptied by step 5 of the migration — read now as the
 * same place in every module. Outside the modules there is {@code core.config}, the datasource and
 * the engines' setup, which belongs to no domain.
 *
 * <h2>Why {@code common.domain} is pure</h2>
 *
 * It carries the calculations that <em>decide</em>: an issue's fingerprint, the gate verdict,
 * the audit integrity chain, the export formats. They touch neither database nor network nor
 * Spring. Three consequences:
 *
 * <ol>
 *   <li>they are exhaustively testable, the only way to check rules whose failure raises no
 *       exception but destroys triage instead;
 *   <li>the same calculation serves the API, the scheduler and the UI — the verdict displayed
 *       <em>is</em> the one the gate returns, not a second one resembling it;
 *   <li>they survive a change of ORM or framework, which is exactly the event this code is
 *       living through.
 * </ol>
 */
@DisplayName("the layer rule")
class ArchitectureTest {

    private static final String ROOT = "com.asmolabs.vectispire";

    private static final String CORE = ROOT + ".core";

    /**
     * The vertical modules — {@code core.<domain>} with {@code web}, {@code internal} and {@code
     * persistence} beneath it (decision 0028). The foundation moved first (step 3 of the migration to
     * Spring Modulith), then the leaf and middle domains (step 4), then the core domains and what was
     * left of the composition roots (step 5, decision 0029): {@code shared} was emptied, {@code
     * maintenance} is the port the periodic jobs are contributed through, and {@code platform} is the
     * shell — the settings screen, the foundation's routes and the API-wide web configuration.
     */
    private static final List<String> MODULES = List.of(
            // Step 3: the foundation.
            "settings", "outbound", "crypto", "audit", "outbox", "reporting",
            // Step 4: the leaf and middle domains, in an order where none reaches a module still to come
            // through anything but the layered packages.
            "siem", "rules", "ai", "threatintel", "tickets", "agents", "notifications", "exports", "gate",
            "inventory", "posture", "compliance", "access",
            // Step 5: the core domains, bottom-up — each only once what it uses was a module — then the
            // periodic jobs' port and the shell that composes several domains for one screen.
            "targets", "scanning", "issues", "maintenance", "platform");

    /**
     * The top-level packages that are no module's. Only {@code config} since step 5: the datasource,
     * the per-engine setup and the migration placeholders serve every module and decide nothing any
     * domain owns. {@code api}, {@code services}, {@code repositories} and {@code persistence} were
     * emptied, and a class put back into one of them fails {@link #everyClassHasAPlace}.
     */
    private static final Set<String> OUTSIDE_MODULES = Set.of("config");

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(ROOT);
    }

    /** The packages each module keeps for one layer, {@code suffixes} under its root. */
    private static String[] layer(String... suffixes) {
        return MODULES.stream()
                .flatMap(module -> Stream.of(suffixes).map(suffix -> CORE + "." + module + suffix))
                .toArray(String[]::new);
    }

    @Test
    @DisplayName("finds classes to check at all")
    void findsSomethingToCheck() {
        // A wrong package name would make every rule below pass without checking
        // anything. That is the failure mode of an architecture suite, so it is asserted
        // first — and against the domain specifically, since that is the package the rules
        // care most about and the one a typo would silently empty.
        org.assertj.core.api.Assertions.assertThat(classes).isNotEmpty();
        org.assertj.core.api.Assertions
                .assertThat(classes.stream()
                        .anyMatch(c -> c.getPackageName().startsWith(ROOT + ".common.domain")))
                .as("the domain package must be on the classpath and populated")
                .isTrue();
        // And every module listed must hold classes in each of the places the rules below read: a
        // module whose name is misspelt here would otherwise be a module no rule applies to.
        for (String module : MODULES) {
            org.assertj.core.api.Assertions
                    .assertThat(classes.stream().anyMatch(c -> c.getPackageName().equals(CORE + "." + module)))
                    .as("module %s has no class at its root: its name in MODULES or its package is wrong", module)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("no layer reaches a layer above it")
    void layersOnlyReachDownwards() {
        layeredArchitecture()
                .consideringOnlyDependenciesInAnyPackage(ROOT + "..")
                .layer("domain").definedBy(ROOT + ".common.domain..")
                .layer("scanning").definedBy(ROOT + ".common.scanning..")
                // A module keeps its entities and its repositories together in `persistence`; they
                // form one layer here, below its services, and `entitiesReachNoRepository` keeps the
                // order between the two that `core.persistence` and `core.repositories` showed until
                // step 5 emptied them.
                .layer("persistence").definedBy(layer(".persistence.."))
                // A module's root is its API and `internal` its implementation: both are the service
                // layer, which the layered packaging calls `services`.
                .layer("services").definedBy(layer("", ".internal.."))
                .layer("api").definedBy(layer(".web.."))

                // Read downwards: who is allowed to see me.
                .whereLayer("api").mayNotBeAccessedByAnyLayer()
                .whereLayer("services").mayOnlyBeAccessedByLayers("api")
                // Not `api`: a controller maps HTTP, a service reads, decides and writes. Thirty-three
                // controllers reached repositories directly when a line here still allowed it; they
                // were moved behind services on 2026-09-24, under a ratchet that shrank to nothing,
                // and since 2026-09-26 no controller names an entity either — see
                // apiNeverTouchesPersistence below.
                .whereLayer("persistence").mayOnlyBeAccessedByLayers("services")
                .whereLayer("scanning").mayOnlyBeAccessedByLayers("services", "api")
                // No optional layers and no empty-should escape any more: every layer is
                // populated, so an empty one is now a package that was renamed or deleted — and
                // this rule going quiet is exactly how that would go unnoticed.
                .check(classes);
    }

    @Test
    @DisplayName("every package of the control plane is a module's, or config")
    void everyClassHasAPlace() {
        // The layer rule constrains the packages it names and nothing else: a class dropped into
        // `core.audit.helpers`, into a new top-level `core.reports`, or back into `core.services`,
        // would belong to no layer and be checked by nothing. So the places are closed: a module's
        // four, or `core.config`.
        ArchCondition<JavaClass> haveAPlace = new ArchCondition<>("sit in a module's root, web, internal or "
                + "persistence package, or in core.config") {
            @Override
            public void check(JavaClass type, ConditionEvents events) {
                String rest = type.getPackageName().substring(CORE.length() + 1);
                String top = rest.contains(".") ? rest.substring(0, rest.indexOf('.')) : rest;
                if (OUTSIDE_MODULES.contains(top)) {
                    return;
                }
                if (MODULES.contains(top)) {
                    String below = rest.substring(top.length());
                    if (below.isEmpty() || Stream.of(".web", ".internal", ".persistence")
                            .anyMatch(place -> below.equals(place) || below.startsWith(place + "."))) {
                        return;
                    }
                }
                events.add(SimpleConditionEvent.violated(type, type.getName() + " is in no module place and not "
                        + "in config: " + type.getPackageName()));
            }
        };
        ArchRuleDefinition.classes()
                .that().resideInAPackage(CORE + "..")
                .and().resideOutsideOfPackage(CORE)
                .should(haveAPlace)
                .check(classes);
    }

    /**
     * The domains every other domain may use: the deployment's settings, the door out, encryption,
     * the audit writer, the outbox relay and the PDF pagination four domains' reports share (decision
     * 0026). Declared to Spring Modulith as its shared modules,
     * on {@link VectispireApplication}, for the same reason (decision 0028).
     *
     * <p>{@code reporting} joined on 2026-09-26, when {@code ReportCursor} left {@code shared}: it is
     * a capability like {@code outbound} — how a page is laid out, not what it says — and a copy per
     * domain would be four answers to "did this page overflow", the defect the class exists for.
     *
     * <p>{@code shared} left it in step 5, empty: its last class, {@code TargetNaming}, went to {@code
     * targets} (decision 0029). No longer a known place, a class dropped back into {@code
     * core.services.shared} fails {@link #everyClassHasAPlace}.
     *
     * <p>{@code maintenance} joined in step 5: the periodic jobs' port. Eight domains contribute a
     * task to the tick, so the port has to sit where every domain may reach it; it names none of
     * them, and the tick that runs the tasks uses nothing but the port (decision 0029).
     */
    private static final Set<String> FOUNDATION =
            Set.of("settings", "outbound", "crypto", "audit", "outbox", "reporting", "maintenance");

    /**
     * What each domain may use besides itself — and, above the foundation, besides the foundation.
     *
     * <p>This is the table of decision 0026, and it is the code as it stood when the flat package
     * was split: every line is a dependency that existed. Adding one is a decision to take in the
     * review that needs it, not a line to append until the build is green — the flat package is
     * what "append until green" produced. {@code platform} is absent on purpose: it is the shell —
     * the settings screen, which composes the credentials and checks of four domains, and the routes
     * of the foundation, which may keep no controller of its own — so it may use any domain, and
     * nothing may use it.
     *
     * <p><b>A module is read whole</b> — its controllers and its entities as well as its services —
     * which the layered packaging never allowed: a service reaching another domain's repository, or a
     * controller calling another domain's service, belonged to no domain and was checked by nothing.
     * The edges that surfaced when a domain became a module are in this table with the reason each
     * exists (decision 0028).
     *
     * <p><b>{@code targets} in most rows since step 5.</b> Every domain that shows, routes or reports
     * on a target names it through {@code TargetNaming}, which sat in {@code shared}, the foundation,
     * while {@code targets} used {@code access} and {@code scanning}. Once {@code targets} used nothing
     * but {@code access} — its figures and its "scan now" became ports — the names could go home, and
     * those domains' dependency on the targets became a line of this table instead of a foundation
     * class; {@code agents}, {@code compliance} and {@code threatintel} joined when they stopped
     * reading the targets' rows and asked {@code TargetCatalog} instead (decision 0029). {@code
     * targets} uses only {@code access}, so none of these lines can close a cycle.
     *
     * <p><b>{@code scanning} likewise</b>, in the rows of {@code gate}, {@code posture}, {@code
     * compliance} and {@code inventory}: they read the scans table through its repository, which the
     * layered packaging let any class name. They ask {@code ScanCatalog} now, the owner's API, and the
     * dependency they always had is written down. {@code scanning} uses only {@code access} and
     * {@code targets}, below all four.
     *
     * <p><b>And {@code issues}</b>, in the rows of {@code ai} (the advisor explains an issue),
     * {@code rules} (a rule set's impact on the open SAST issues) and {@code threatintel} (the feed
     * re-evaluates the backlog's exploitation): they read the issues table through the layered
     * repository and ask {@code IssueCatalog} now. {@code issues} uses {@code access}, {@code targets}
     * and {@code scanning}, none of which uses these three.
     */
    private static final Map<String, Set<String>> MAY_USE = Map.ofEntries(
            Map.entry("settings", Set.of()),
            Map.entry("outbound", Set.of()),
            // `settings` since the foundation became modules: the document signing key is kept in a
            // `t_setting` row, which `crypto` read and wrote through the repository. Now through
            // `SettingsService`; `settings` uses nothing, so no cycle can close.
            Map.entry("crypto", Set.of("outbound", "settings")),
            Map.entry("audit", Set.of()),
            // `maintenance` since step 5: the relay and the purge of delivered messages are the
            // outbox's contributions to the periodic tick, and a foundation module reaches another
            // only through this table. `maintenance` uses nothing, so no cycle can close.
            Map.entry("outbox", Set.of("maintenance")),
            Map.entry("maintenance", Set.of()),
            Map.entry("reporting", Set.of()),
            Map.entry("access", Set.of()),
            Map.entry("siem", Set.of()),
            // `inventory` since inventory became a module: rule coverage compares the rule sets with the
            // package URLs the components inventory holds, which it read through the repository.
            // `inventory` uses nothing above the foundation.
            // `scanning` since step 5, and in place of `scanning` -> `rules`: a scan asks which rule set
            // is active and fetches its files through `ScanRuleSets`, a port `scanning` declares and
            // `rules` implements. Called the other way, `scanning` -> `rules` -> `inventory` ->
            // `scanning` would be a cycle once the inventory reads scans through their module.
            Map.entry("rules", Set.of("inventory", "issues", "scanning")),
            // `scanning` since step 5, and in place of `scanning` -> `inventory`: the inventory reads
            // scans and findings (licences, SBOM diff, blast radius, the purge's selection), while a
            // scan's components and API surface reach it through `ScanIngestor.InventorySink`, a port
            // `scanning` declares and `inventory` implements.
            Map.entry("inventory", Set.of("scanning", "targets")),
            Map.entry("ai", Set.of("access", "issues")),
            // `targets` since step 5: an issue belongs to a target, is named through `TargetNaming` and
            // answers the listings' open counts through `TargetBacklog`, a port `targets` declares.
            // `scanning` since step 5, and in place of `scanning` -> `issues`: the backlog reads scans and
            // findings for its history and its sightings, and deletes an issue's findings through
            // `scanning` when a target goes; a completed scan's findings reach the backlog through
            // `ScanIngestor.Backlog`, a port `scanning` declares and `issues` implements.
            Map.entry("issues", Set.of("access", "scanning", "targets")),
            // `gate` since step 5 gave the stored policies to gate: the sweep opens a ticket only for an
            // issue the policy of its scope would fail on, so it evaluates the gate, and asks `gate`
            // for the policies in force instead of reading their table from below it. `gate` uses
            // nothing that uses `tickets` (the tracker implements `issues`' `TicketReferences`).
            Map.entry("tickets", Set.of("access", "gate", "issues", "targets")),
            // `targets` since step 5: a scan is of a target — the dispatcher reads its row and
            // credentials, the scheduler its schedule — and the target screens' latest scan and "scan
            // now" are answered through `TargetScans`, a port `targets` declares.
            Map.entry("scanning", Set.of("access", "targets")),
            // `rules` since agents became a module and took its controllers: a remote agent fetches the
            // rule set a task names by its hash (`AgentsController.ruleSet`). `rules` uses nothing
            // above the foundation.
            Map.entry("agents", Set.of("access", "rules", "scanning", "targets")),
            // Not `scanning` any more, nor `issues` (step 5): the listings' figures and the scan trigger
            // are ports `targets` declares, so every domain that names a target can depend on it,
            // and the purge of a deleted target can be an event `targets` owns.
            Map.entry("targets", Set.of("access")),
            Map.entry("threatintel", Set.of("issues", "scanning", "siem", "targets")),
            // `access` since gate became a module: its register is purged past the evidence window by
            // the authentication tables' pass, which now reaches it through a port gate implements
            // (`SessionCleanupService.EvidencePurge`) instead of reading its repository. The reverse
            // read had closed a cycle; `access` uses nothing above the foundation.
            Map.entry("gate", Set.of("access", "issues", "rules", "scanning", "siem", "targets")),
            // `access` since access became a module: a scan's delta is routed to the teams granted its
            // target that have a channel, and a team message is posted to that channel — both tables
            // access writes, which routing read through their repositories (now `TeamChannels`).
            // `access` uses nothing above the foundation.
            // Not `scanning` since step 5: a scan's delta is the backlog's, announced through
            // `ScanDelta.Sink`, a port of `issues`; it was `ScanIngestor.NotificationSink`.
            Map.entry("notifications", Set.of("access", "issues", "targets")),
            // `scanning` since exports became a module and took its controllers: a document is made
            // for a scan, and its route first refuses a scan the caller may not see
            // (`ScanDocumentService.requireVisible`). `scanning` does not use `exports`.
            Map.entry("exports", Set.of("gate", "issues", "scanning", "targets")),
            Map.entry("posture",
                    Set.of("access", "gate", "inventory", "issues", "notifications", "scanning", "targets")),
            Map.entry("compliance",
                    Set.of("access", "ai", "exports", "gate", "inventory", "issues", "posture", "rules", "scanning",
                            "targets")));

    private static final String PLATFORM = "platform";

    /**
     * What any module's controllers may use beyond their own module's table row: {@code access}, which
     * authenticates the caller and resolves what they may see. Every route needs the principal and its
     * marker, and every route naming a target resolves a {@code Visibility}; a table row per module
     * repeating it would be noise. It cannot close a cycle: {@code access} uses nothing above the
     * foundation.
     */
    private static final String EVERY_ROUTE_USES = "access";

    /**
     * A dependency that points against the table and closes a cycle, kept because breaking it is
     * more than a package move — each says why, and what would remove it.
     */
    private record KnownCycle(Class<?> origin, Class<?> target, String reason) {}

    /**
     * <b>A list that only shrinks, and has.</b> Two entries on 2026-09-26, both between domains
     * whose classes sat where the future modules would own them (decision 0026). Both were broken
     * the same day without moving a class: {@code audit} → {@code siem} by the {@code
     * AuditChainBroken} event the SIEM listens to, {@code issues} → {@code tickets} by the {@code
     * TicketReferences} port the tracker implements. The mechanism stays so that a cycle which cannot
     * be broken in the review that finds it is recorded with its reason rather than hidden by moving a
     * class to the wrong domain; {@link #knownCyclesAreStillThere} fails the day an entry goes stale.
     */
    private static final List<KnownCycle> KNOWN_CYCLES = List.of();

    /**
     * The module a class belongs to — {@code core.<module>} and everything beneath it — or empty
     * outside any: {@code core.config} and the application class belong to no domain.
     */
    private static Optional<String> domainOf(JavaClass type) {
        String name = type.getPackageName();
        return MODULES.stream()
                .filter(module -> name.equals(CORE + "." + module) || name.startsWith(CORE + "." + module + "."))
                .findFirst();
    }

    /** A module's root package: its API, what another module may call. */
    private static boolean isModuleRoot(JavaClass type, String module) {
        return type.getPackageName().equals(CORE + "." + module);
    }

    private static boolean isWeb(JavaClass type) {
        return MODULES.stream().anyMatch(module -> type.getPackageName().equals(CORE + "." + module + ".web")
                || type.getPackageName().startsWith(CORE + "." + module + ".web."));
    }

    /**
     * Exposed beyond the module root through Spring Modulith's own declaration: a package whose
     * {@code package-info} carries {@link NamedInterface}, or a type that does. Read from the
     * annotation rather than listed here, so this rule and step 6's {@code verify()} cannot disagree
     * about what a module publishes.
     */
    private static boolean isNamedInterface(JavaClass type) {
        JavaClass top = type;
        while (top.getEnclosingClass().isPresent()) {
            top = top.getEnclosingClass().get();
        }
        return top.isAnnotatedWith(NamedInterface.class) || type.getPackage().isAnnotatedWith(NamedInterface.class);
    }

    /** The class itself, its nested classes and its lambdas' holders — what a source file owns. */
    private static boolean ownedBy(JavaClass type, Class<?> owner) {
        return type.getName().equals(owner.getName()) || type.getName().startsWith(owner.getName() + "$");
    }

    private static boolean isKnownCycle(Dependency dependency) {
        return KNOWN_CYCLES.stream().anyMatch(known -> ownedBy(dependency.getOriginClass(), known.origin())
                && ownedBy(dependency.getTargetClass(), known.target()));
    }

    private static boolean mayUse(String from, String to) {
        return MAY_USE.getOrDefault(from, Set.of()).contains(to)
                || (!FOUNDATION.contains(from) && FOUNDATION.contains(to));
    }

    @Test
    @DisplayName("the domains form no cycle but the ones recorded")
    void domainsFormNoCycle() {
        // A cycle between two domains makes them one domain with two names: neither can be read,
        // tested or changed without the other. Sliced by module rather than by package: a module's
        // `web`, `internal` and `persistence` are the module, and a cycle through them is one.
        SliceAssignment byDomain = new SliceAssignment() {
            @Override
            public SliceIdentifier getIdentifierOf(JavaClass type) {
                return domainOf(type).map(SliceIdentifier::of).orElse(SliceIdentifier.ignore());
            }

            @Override
            public String getDescription() {
                return "the modules";
            }
        };
        SliceRule rule = SlicesRuleDefinition.slices().assignedFrom(byDomain).should().beFreeOfCycles();
        for (KnownCycle known : KNOWN_CYCLES) {
            rule = rule.ignoreDependency(
                    DescribedPredicate.describe(known.origin().getSimpleName(), type -> ownedBy(type, known.origin())),
                    DescribedPredicate.describe(known.target().getSimpleName(), type -> ownedBy(type, known.target())));
        }
        rule.check(classes);
    }

    @Test
    @DisplayName("a recorded cycle is still a cycle, or it leaves the list")
    void knownCyclesAreStillThere() {
        for (KnownCycle known : KNOWN_CYCLES) {
            boolean present = classes.stream()
                    .filter(type -> ownedBy(type, known.origin()))
                    .flatMap(type -> type.getDirectDependenciesFromSelf().stream())
                    .anyMatch(dependency -> ownedBy(dependency.getTargetClass(), known.target()));
            org.assertj.core.api.Assertions.assertThat(present)
                    .as("%s no longer depends on %s: remove it from KNOWN_CYCLES",
                            known.origin().getSimpleName(), known.target().getSimpleName())
                    .isTrue();
        }
    }

    @Test
    @DisplayName("a domain uses only the domains it is allowed")
    void domainsDependOnlyWhereAllowed() {
        // Acyclic is not enough: a new dependency pointing the wrong way can be acyclic today and
        // close a cycle with the next one. The table fixes the direction.
        ArchCondition<JavaClass> useOnlyAllowedDomains =
                new ArchCondition<>("use only the domains decisions 0026 and 0028 allow") {
                    @Override
                    public void check(JavaClass type, ConditionEvents events) {
                        // `platform` may use every module; `config` belongs to none and is the residence
                        // rule's to keep small.
                        String from = domainOf(type).orElse(PLATFORM);
                        if (from.equals(PLATFORM)) {
                            return;
                        }
                        boolean web = isWeb(type);
                        for (Dependency dependency : type.getDirectDependenciesFromSelf()) {
                            Optional<String> to = domainOf(dependency.getTargetClass());
                            if (to.isEmpty() || to.get().equals(from) || mayUse(from, to.get())
                                    || (web && to.get().equals(EVERY_ROUTE_USES))
                                    || isKnownCycle(dependency)) {
                                continue;
                            }
                            events.add(SimpleConditionEvent.violated(dependency, dependency.getDescription()
                                    + " — " + from + " may not use " + to.get()));
                        }
                    }
                };
        ArchRuleDefinition.classes()
                .that().resideInAnyPackage(MODULES.stream().map(module -> CORE + "." + module + "..")
                        .toArray(String[]::new))
                .should(useOnlyAllowedDomains)
                .check(classes);
    }

    @Test
    @DisplayName("a module reaches another module through its API, never through its internals")
    void modulesMeetAtTheirApi() {
        // What Spring Modulith's `verify()` will enforce at step 6, enforced now between the modules
        // that exist: another module's root package, or what it publishes as a named interface — never
        // its `internal`, `persistence` or `web`. A module reading another's repository is the coupling
        // the layered packaging hid, and the one a module boundary exists to show. Every class of the
        // control plane but `core.config` is a module's since step 5, so every one is held to it.
        ArchCondition<JavaClass> meetAtTheApi = new ArchCondition<>("use another module only through its root "
                + "package or a named interface") {
            @Override
            public void check(JavaClass type, ConditionEvents events) {
                String from = domainOf(type).orElseThrow();
                for (Dependency dependency : type.getDirectDependenciesFromSelf()) {
                    JavaClass target = dependency.getTargetClass();
                    Optional<String> to = domainOf(target).filter(MODULES::contains);
                    if (to.isEmpty() || to.get().equals(from) || isModuleRoot(target, to.get())
                            || isNamedInterface(target)) {
                        continue;
                    }
                    events.add(SimpleConditionEvent.violated(dependency, dependency.getDescription()
                            + " — " + target.getPackageName() + " is internal to " + to.get()));
                }
            }
        };
        if (MODULES.isEmpty()) {
            return;
        }
        ArchRuleDefinition.classes()
                .that().resideInAnyPackage(MODULES.stream().map(module -> CORE + "." + module + "..").toArray(String[]::new))
                .should(meetAtTheApi)
                .check(classes);
    }

    @Test
    @DisplayName("a module's controllers call its API, not its internals")
    void controllersCallTheirModuleApi() {
        // `internal` is what the API is built from. A controller reaching into it makes the class it
        // reaches part of the module's surface without saying so; if a route needs it, it belongs at
        // the root. Persistence is `webNeverTouchesPersistence`'s.
        for (String module : MODULES) {
            ArchRuleDefinition.noClasses()
                    .that().resideInAPackage(CORE + "." + module + ".web..")
                    .should().dependOnClassesThat().resideInAPackage(CORE + "." + module + ".internal..")
                    .allowEmptyShould(true)
                    .check(classes);
        }
    }

    @Test
    @DisplayName("an entity reaches no repository")
    void entitiesReachNoRepository() {
        // The order `core.persistence` → `core.repositories` gave for free, kept inside a module's
        // single `persistence` package: an entity describes a table, a repository reads it.
        ArchRuleDefinition.noClasses()
                .that().areAnnotatedWith("jakarta.persistence.Entity")
                .or().areAnnotatedWith("jakarta.persistence.Embeddable")
                .should().dependOnClassesThat().areAssignableTo("org.springframework.data.repository.Repository")
                .check(classes);
    }

    @Test
    @DisplayName("nothing of the persistence layer reaches the api layer, not even for one call")
    void apiNeverTouchesPersistence() {
        // `SchemaNameCollisionTest` keeps entities out of responses; this keeps them out of `api`
        // altogether. Twenty-five classes of `api` named a persistence type when this was added,
        // the principal among them: it carried the account's password hash and TOTP secret to every route, and a
        // controller could hand a row back to a service that saved whatever had been done to it.
        // Services answer with records named `…View` now. No exception list and no freeze: a
        // controller that needs a row needs a service method instead. Every module's `web` is held
        // to it, against every module's `persistence`, its own included — and against the
        // repositories a module keeps beside its entities, and the query records it publishes as a
        // named interface, which the layer rule alone would let a controller name as a type.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".web.."))
                .should().dependOnClassesThat().resideInAnyPackage(CORE + ".*.persistence..")
                .check(classes);
    }

    @Test
    @DisplayName("the api layer opens no transaction: a transaction is a decision, and decisions are the services'")
    void apiOpensNoTransaction() {
        // The layering above keeps `api` out of the repositories; this keeps it out of the
        // transaction boundary, which is the other half of "a controller maps HTTP". Three
        // controllers held a `TransactionTemplate` or `@Transactional` before the move.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".web.."))
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("org.springframework.transaction.support.TransactionTemplate")
                .orShould().dependOnClassesThat()
                .haveFullyQualifiedName("org.springframework.transaction.annotation.Transactional")
                .check(classes);
    }

    /** Where the filter chain lives: {@code access} took it with it from {@code core.api.security} (decision 0028). */
    private static final String SECURITY_WEB = CORE + ".access.web.security..";

    @Test
    @DisplayName("no controller writes the audit log: the service that performs an action records it")
    void controllersWriteNoAuditEntry() {
        // An entry written by the route is an entry the next caller of the same service does not
        // write — a second route, a scheduled job — and whether it is written before or after the
        // commit becomes each controller's own guess. Ten controllers still held `AuditLogService`
        // when this was added. The security web layer is left out on purpose: the filter chain
        // audits what happens before any controller runs — a refused bearer token, a denied route, a
        // single-sign-on callback — events that belong to no service method the entry could move to.
        // Named by class literal, not by string: the class moved package once, and a string naming
        // where it used to be would have left this rule checking nothing.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".web.."))
                .and().resideOutsideOfPackage(SECURITY_WEB)
                .should().dependOnClassesThat()
                .haveFullyQualifiedName(AuditLogService.class.getName())
                .orShould().dependOnClassesThat()
                .haveFullyQualifiedName(AuditLogService.Record.class.getName())
                .check(classes);
    }

    @Test
    @DisplayName("the domain depends on no framework and no driver")
    void domainIsPure() {
        // A pure calculation importing Hibernate stops being testable without a database;
        // one importing Spring stops being reusable outside the server. Both are how a
        // domain layer quietly becomes a service layer.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".common.domain..")
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        "org.springframework..",
                        "jakarta.persistence..",
                        "org.hibernate..",
                        "java.sql..",
                        "javax.sql..",
                        "org.flywaydb..",
                        "liquibase..",
                        // The scanning half of `vectispire-common` needs a Docker client; the
                        // domain half must never. A calculation that reached the daemon would
                        // stop being testable without one, which is the property the whole
                        // layer exists for.
                        "com.github.dockerjava..")
                .check(classes);
    }

    @Test
    @DisplayName("only the repositories speak SQL")
    void onlyRepositoriesReachTheDatabase() {
        // A module's repositories sit in its `persistence` package, which is therefore the one place
        // of a module left out; its root, `internal` and `web` are held to the rule, as `core.services`
        // and `core.api` were before step 5 emptied them.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(Stream.concat(
                                Stream.of(layer("", ".internal..")),
                                Stream.of(layer(".web..")))
                        .toArray(String[]::new))
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.sql..", "javax.sql..", "org.hibernate..")
                .check(classes);
    }

    @Test
    @DisplayName("an outbound call goes through the door that validates and pins")
    void onlyTheOutboundDoorSpeaksHttpOutwards() {
        // **The rule the guard cannot enforce for itself.** `OutboundUrlGuard` refuses a URL
        // resolving to link-local or, for the model review, to anything public — and none of
        // that happens if a seventh caller builds its own client and calls a setting straight.
        // Nothing about such a call looks wrong: it works perfectly, right up to the redirect
        // or the rebind. The three classes named below are the only ones allowed to hold a
        // client, and each one validates first.
        //
        // `03-security.md` claimed this rule existed for as long as it did not: it described
        // the NestJS suite, which was not carried over. Written down now, in the place that
        // fails.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core..")
                // Matched on the full name rather than the simple one, so a nested or
                // anonymous class counts as its owner: the resolver inside `PinnedHttpSender`
                // is an anonymous `DnsResolver`, whose simple name is empty, and a simple-name
                // exclusion silently failed to cover it.
                .and().haveNameNotMatching(".*\\.(PinnedHttpSender|OutboundPost|OutboundJson)(\\$.*)?")
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.net.http..", "org.apache.hc..")
                .check(classes);
    }

    @Test
    @DisplayName("a raw socket is opened by the syslog sender alone, to the address the guard pinned")
    void onlySyslogSenderOpensSockets() {
        // The HTTP rule above says nothing about `java.net.Socket`: a second class opening one
        // would reach the metadata endpoint or the Docker proxy with no guard in the way, and
        // would look like a perfectly ordinary TCP client in review.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core..")
                .and().haveNameNotMatching(".*\\.SyslogSender(\\$.*)?")
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("java.net.Socket")
                .orShould().dependOnClassesThat().haveFullyQualifiedName("java.net.DatagramSocket")
                .orShould().dependOnClassesThat().haveFullyQualifiedName("java.nio.channels.SocketChannel")
                .orShould().dependOnClassesThat().haveFullyQualifiedName("java.nio.channels.DatagramChannel")
                .orShould().dependOnClassesThat().resideInAPackage("javax.net..")
                .check(classes);
    }

    @Test
    @DisplayName("an entity describes a table and nothing else")
    void persistenceHasNoWebOrService() {
        // Dependency injection is not an entity's business, and neither is HTTP.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".persistence.."))
                .should().dependOnClassesThat()
                .resideInAnyPackage("org.springframework.web..", "jakarta.servlet..")
                .check(classes);
    }

    @Test
    @DisplayName("every repository write carries @Transactional")
    void everyRepositoryWriteIsTransactional() {
        // Written in `core.repositories`' package-info for as long as the package existed, and true
        // of every module's repositories since; step 5 emptied the package, and the convention came
        // here rather than into a document. Spring Data makes its derived and inherited methods
        // transactional but not a custom modifying query, so one written without the annotation
        // fails outright when no caller has opened a transaction — and works when one has, which is
        // how the omission survives review and reaches production as an intermittent failure. The
        // derived `deleteBy…` methods are held to it too: they have no annotation to prompt the
        // question, and fail at runtime with "No EntityManager with actual transaction available"
        // rather than at startup.
        DescribedPredicate<com.tngtech.archunit.core.domain.JavaMethod> writes = DescribedPredicate.describe(
                "write rows",
                method -> method.isAnnotatedWith("org.springframework.data.jpa.repository.Modifying")
                        || method.getName().matches("(delete|remove)(All)?By.+"));
        ArchRuleDefinition.methods()
                .that().areDeclaredInClassesThat().areAssignableTo("org.springframework.data.repository.Repository")
                .and(writes)
                .should().beAnnotatedWith("org.springframework.transaction.annotation.Transactional")
                .orShould().beDeclaredInClassesThat()
                .areAnnotatedWith("org.springframework.transaction.annotation.Transactional")
                .check(classes);
    }

    @Test
    @DisplayName("case is folded without the host's locale")
    void caseIsFoldedWithoutTheHostLocale() {
        // `toUpperCase()` folds with the JVM's default locale. On a host set to Turkish, "i" becomes
        // "İ": a severity, a scope, an HTTP method or a framework name stops matching the constant
        // it was compared with, and a path lower-cased into a fingerprint changes with the machine
        // that scanned it. Forty-seven calls did it; `Locale.ROOT` is the only spelling allowed.
        ArchRuleDefinition.noClasses()
                .should().callMethod(String.class, "toUpperCase")
                .orShould().callMethod(String.class, "toLowerCase")
                .check(classes);
    }
}

import org.gradle.api.tasks.PathSensitivity
plugins {
    id("vectispire.java-conventions")
    alias(libs.plugins.springBoot)
    alias(libs.plugins.jib)
}

/**
 * The control plane: schema, repositories, use cases, HTTP API, agent protocol.
 *
 * Internally it keeps the layer rule the NestJS tree enforced, inside every domain module
 * (decisions 0028 and 0029) — the layers the packages used to be, one place each in a module:
 *
 * ```
 *   web ──► root and internal ──► persistence ──► database
 *                 │                    │
 *                 └─────────┬──────────┘
 *                           ▼
 *                   vectispire-common
 * ```
 *
 * **Only the repositories may speak SQL** — each module's `persistence`.
 * Not for purity: the behaviour the engines disagree about — locking, upsert, boolean width,
 * timestamp precision — has to sit where a portability suite can reach it, and that is there. A
 * service writing a query fails `ArchitectureTest`.
 *
 * The four drivers are `runtimeOnly`. They must be in the image, and no compiled class may
 * name one: a class importing `org.postgresql` is a class that stopped working on the other
 * three, which is a failure a portability campaign should catch before an operator does.
 */
/**
 * The interface, bundled into the jar.
 *
 * **Off by default, and that is the point.** Wiring the Angular build into every
 * `./gradlew build` would put Node on the critical path of a backend change and add a minute
 * to a loop somebody runs fifty times a day — and CI's JVM job has no Node at all.
 *
 * Two ways to turn it on:
 *
 * ```
 * ./gradlew bootJar -Pui                    # builds the interface here, needs Node
 * ./gradlew bootJar -PuiDist=/path/browser  # takes one already built
 * ```
 *
 * The second exists for the container image, where the interface is built in a Node stage and
 * the jar in a JDK stage. Without it the JDK image would need Node installed to run a build it
 * has no other reason to know about.
 *
 * With either, one jar serves the API and the interface from **one origin**. That removes the
 * dev proxy from production, makes `connect-src 'self'` true rather than aspirational, and
 * makes a deployment one artifact instead of two that have to agree on a port.
 */
val uiSource = layout.projectDirectory.dir("../../vectispire-angular")
val uiOutput = layout.buildDirectory.dir("angular")

val buildUi by tasks.registering(Exec::class) {
    // Declared so Gradle can skip the whole thing when nothing changed. Without these the task
    // re-runs on every build, which is most of what makes bundling a UI feel expensive.
    inputs.dir(uiSource.dir("src"))
    inputs.file(uiSource.file("package.json"))
    inputs.file(uiSource.file("angular.json"))
    outputs.dir(uiOutput)

    workingDir = uiSource.asFile
    commandLine("npx", "ng", "build", "--configuration", "production", "--output-path",
                uiOutput.get().asFile.absolutePath)
}

val prebuiltUi = providers.gradleProperty("uiDist")

if (prebuiltUi.isPresent || project.hasProperty("ui")) {
    tasks.named<ProcessResources>("processResources") {
        val assets = if (prebuiltUi.isPresent) {
            files(prebuiltUi.get())
        } else {
            files(buildUi.map { uiOutput.get().dir("browser") })
        }
        // `static/` is where Spring Boot serves from with no configuration. The SPA's deep
        // links still need forwarding — see `SpaForwarding`.
        from(assets) { into("static") }
    }
}

dependencies {
    implementation(project(":vectispire-common"))
    implementation(platform(libs.spring.boot.bom))
    testImplementation(platform(libs.spring.boot.bom))

    /*
     * **Tomcat, une version devant ce que Spring Boot gère — et c'est temporaire par construction.**
     *
     * Trois avis critiques portent sur `tomcat-embed-core` avant 11.0.25 (GHSA-9xv2-5v5q-p794,
     * GHSA-h3x4-894j-xpx5, GHSA-gcx9-497g-6cp6). Le BOM de Spring Boot 4.1.1 s'arrête à 11.0.24 :
     * monter Spring Boot règle jackson et log4j, pas celui-ci. La barrière de vulnérabilités du
     * pipeline échoue dessus, et un produit qui refuse aux autres ce qu'il tolère chez lui n'a pas
     * d'argument.
     *
     * `require` et non `strictly` : la contrainte pose un plancher, elle ne fige rien. Le jour où
     * le BOM passe à 11.0.25 ou au-delà, c'est lui qui gagne et ce bloc devient du bruit — **le
     * supprimer est alors la bonne action**, et cette phrase est là pour que personne n'ait à se
     * demander s'il ose.
     *
     * Les trois artefacts ensemble : `el` et `websocket` sont versionnés avec `core` en amont, et
     * n'en monter qu'un produirait un écart que rien ne rattrape.
     */
    constraints {
        listOf("tomcat-embed-core", "tomcat-embed-el", "tomcat-embed-websocket").forEach { artifact ->
            implementation("org.apache.tomcat.embed:$artifact") {
                version { require("11.0.25") }
                because("GHSA-9xv2-5v5q-p794, GHSA-h3x4-894j-xpx5, GHSA-gcx9-497g-6cp6")
            }
        }
    }

    implementation("org.springframework.boot:spring-boot-starter-web")
    // **Declared, though it was already on the classpath through docker-java's transport.**
    // `PinnedHttpSender` needs a client that takes a DNS resolver per instance, which the JDK's
    // does not offer; depending on it by accident is not depending on it. The version comes from
    // the catalog, where the advisories that raised it are named.
    implementation(libs.apache.httpclient5)
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    // The OIDC client, for the optional single sign-on. `oauth2-client` and not
    // `oauth2-resource-server`: Keycloak authenticates, and Vectispire still issues its own session
    // — see `OidcConfiguration` for why the token is not validated on every request instead.
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    // The mail sender. Its own starter rather than a raw JavaMail dependency: the retry, the
    // encoding and the session handling are the parts nobody should rewrite.
    implementation("org.springframework.boot:spring-boot-starter-mail")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // **In `vectispire-core` and not in the domain beside the other exports**, deliberately. The
    // domain half of `vectispire-common` is what the agent also carries, and an agent that never
    // renders a document has no business shipping a PDF library. The layer rule would have
    // allowed it — it forbids frameworks and drivers, and PDFBox is neither — so the reason is
    // the agent's classpath rather than the rule.
    // Cloning the upstream rule catalogue at a pinned tag. `vectispire-common` keeps JGit as
    // `implementation`, so it does not reach here transitively — and declaring it explicitly is
    // the honest form anyway: this module uses it directly.
    implementation(libs.jgit)
    implementation(libs.pdfbox)
    implementation(libs.bucket4j.core)
    implementation(libs.springdoc.openapi.starter.webmvc.ui)
    /*
     * **Spring Modulith, to verify the module boundaries.** `ModularityTest` fails the build on what it
     * finds and writes its report and diagrams (decision 0030); at runtime it
     * is inert — no event publication registry (that needs a `spring-modulith-starter-jpa` or `-jdbc`
     * this build does not declare: the outbox is the one answer to "did this effect leave", decision
     * 0025) and no actuator endpoint (`spring-modulith-actuator` is not declared either). The core
     * starter is on the main classpath because the module annotations (`@ApplicationModule`,
     * `@NamedInterface`) will live in production code from step 3 of the migration on.
     */
    implementation(platform(libs.spring.modulith.bom))
    implementation(libs.spring.modulith.starter.core)
    implementation(libs.flyway.core)
    implementation(libs.flyway.database.postgresql)
    implementation(libs.flyway.mysql)
    implementation(libs.spring.boot.flyway)

    runtimeOnly(libs.postgresql)
    runtimeOnly(libs.mysql)
    runtimeOnly(libs.sqlite)
    // SQLite is not one of Hibernate's own dialects. It is a first-class engine here, so the
    // community dialect is not optional — without it the schema check simply cannot run on the
    // one engine that needs no daemon.
    runtimeOnly(libs.hibernate.community.dialects)

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit.junit5)
    testImplementation(platform(libs.spring.modulith.bom))
    testImplementation(libs.spring.modulith.starter.test)
    // SQLite on the unit-test classpath, not only at runtime: it is the one engine that needs
    // no daemon, so the migrations can be executed for real in a plain unit test. PostgreSQL
    // and MySQL are the integration campaign's business.
    testRuntimeOnly(libs.sqlite)
    testImplementation(libs.sqlite)
    // BouncyCastle's certificate builder, for the TLS syslog collector the SIEM tests stand up:
    // its certificate is generated in the test rather than committed, so there is no key in the
    // repository and nothing that expires. Already on the runtime classpath through
    // vectispire-common; declared here because depending on something by accident is not
    // depending on it.
    testImplementation(libs.bouncycastle)
    testImplementation(libs.bouncycastle.pkix)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

/**
 * The integration campaign, kept apart from the unit tests because it needs Docker and runs
 * in minutes rather than seconds.
 *
 * **No "skip if the database is missing" guard, deliberately.** A suite that skips itself
 * reports green without having checked anything, which is worse than one that fails.
 */
val integrationTest: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations["integrationTestImplementation"].extendsFrom(configurations.testImplementation.get())
configurations["integrationTestRuntimeOnly"].extendsFrom(configurations.testRuntimeOnly.get())

dependencies {
    // Versions from the Spring Boot BOM, which already manages Testcontainers. A second BOM
    // here would be a second authority for one version, and the mismatch surfaces as a missing
    // class rather than as a conflict.
    "integrationTestImplementation"(platform(libs.spring.boot.bom))
    // Testcontainers 2.x prefixes every module with `testcontainers-`; the 1.x names resolve to
    // nothing at all rather than to an older version.
    "integrationTestImplementation"("org.testcontainers:testcontainers-junit-jupiter")
    "integrationTestImplementation"("org.testcontainers:testcontainers-postgresql")
    "integrationTestImplementation"("org.testcontainers:testcontainers-mysql")
    "integrationTestImplementation"("org.springframework.boot:spring-boot-testcontainers")
}

val integrationTestTask = tasks.register<Test>("integrationTest") {
    description = "Runs the campaign against a real server for one dialect."
    group = "verification"
    testClassesDirs = integrationTest.output.classesDirs
    classpath = configurations["integrationTestRuntimeClasspath"] +
        integrationTest.output +
        sourceSets.main.get().output
    // The suites share one server, so they cannot run against it concurrently.
    maxParallelForks = 1
    systemProperty("vectispire.db.dialect", providers.gradleProperty("dialect").getOrElse("mysql"))
    shouldRunAfter(tasks.test)
}

/**
 * The two supported engines, plus the fixture the unit suite runs on.
 *
 * A portability defect only shows up by running them — PostgreSQL and MySQL have each produced
 * one that was invisible on the other. SQLite is here for a different reason: it is what the HTTP
 * suite uses, so its migrations have to apply even though **it is not a deployable engine** —
 * see decision 0014.
 */
val engines = listOf("postgres", "mysql", "sqlite")

engines.forEach { engine ->
    tasks.register<Test>("integrationTest${engine.replaceFirstChar { it.uppercase() }}") {
        description = "Runs the campaign against $engine."
        group = "verification"
        testClassesDirs = integrationTest.output.classesDirs
        classpath = configurations["integrationTestRuntimeClasspath"] +
            integrationTest.output +
            sourceSets.main.get().output
        maxParallelForks = 1
        systemProperty("vectispire.db.dialect", engine)
        // Each engine gets its own results directory: one shared directory means the last run
        // overwrites the others, and "which engine failed" stops being answerable.
        reports.junitXml.outputLocation = layout.buildDirectory.dir("test-results/integrationTest-$engine")
        reports.html.outputLocation = layout.buildDirectory.dir("reports/tests/integrationTest-$engine")
    }
}

/**
 * Le realm livré est une entrée du test qui le garde.
 *
 * **Sans cette déclaration, Gradle a caché un succès périmé.** `ShippedRealmTest` lit
 * `ci/keycloak/vectispire-realm.json`, un fichier hors du module : la tâche de test le croyait
 * inchangé, se déclarait à jour et rejouait un ancien résultat. Vérifié en cassant le realm —
 * le cas passait au vert, et n'échouait qu'avec `--rerun-tasks`. Un test qui peut silencieusement
 * ne pas tourner est pire qu'une absence de test : il rapporte vert sans avoir rien contrôlé.
 */
tasks.named<Test>("test") {
    inputs.file(rootProject.file("../ci/keycloak/vectispire-realm.json"))
        .withPropertyName("shippedKeycloakRealm")
        .withPathSensitivity(PathSensitivity.RELATIVE)

    // Même raison, même piège : `RoleSetsMatchTheEnumTest` lit le magasin de session du front,
    // hors du module. Sans la déclaration, changer ce fichier laisse la tâche « à jour ».
    inputs.file(rootProject.file("../vectispire-angular/src/app/core/session.store.ts"))
        .withPropertyName("frontendSessionStore")
        .withPathSensitivity(PathSensitivity.RELATIVE)

    // `MigrationLayoutTest` holds the campaign's probe migration to the rules of a common one, and
    // the probe sits in the integration sources, which the unit task does not otherwise read.
    inputs.dir("src/integrationTest/resources/db/migration-test")
        .withPropertyName("probeMigrations")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

tasks.register("integrationTestAll") {
    description = "Runs the campaign on both supported engines and the SQLite fixture."
    group = "verification"
    dependsOn(engines.map { "integrationTest${it.replaceFirstChar { c -> c.uppercase() }}" })
}

/**
 * A stable jar name, because four other files already assume one.
 *
 * `gradle.properties` sets a project version, so `bootJar` produced `vectispire-core-0.9.0.jar`
 * while `Dockerfile`, `Dockerfile.agent`, `release.yml` and the nightly workflow all copy
 * `vectispire-core.jar`. Every one of those steps failed on a file that never existed — and nothing
 * noticed, because at the time no CI job built the images or ran a release.
 *
 * Pinned here rather than by teaching four callers to glob a version they do not care about:
 * the version belongs in the manifest and in the release artifact's name, which `release.yml`
 * applies itself when it renames the file.
 */
tasks.named<Jar>("bootJar") {
    archiveFileName = "vectispire-core.jar"
}

/**
 * `META-INF/build-info.properties`, so a signed document can say which version produced it.
 *
 * The in-toto statement and the CycloneDX SBOM both wrote the literal "0.9.0", and every release
 * after that one would have gone on claiming it. Spring Boot reads this file into `BuildProperties`.
 * **Without the build time**: a timestamp in a resource makes every build a different jar and a
 * different Jib layer, for a field nothing reads.
 */
springBoot {
    buildInfo {
        excludes = setOf("time")
    }
}

/**
 * The container image, built from this build rather than from a Dockerfile.
 *
 * **Why Jib.** The image and the release both copied `vectispire-core.jar` while `bootJar` emitted
 * `vectispire-core-0.9.0.jar`, so both were broken for an unknown period and were found by
 * accident. Jib removes the class of defect rather than the instance: there is no path string
 * between the build and the image to get wrong, because the build *is* the image.
 *
 * **No `git`, no `openssh-client`, and that was verified rather than assumed.** The Dockerfile
 * installed both. Nothing shells out to either — cloning goes through JGit (`org.eclipse.jgit`)
 * and its own SSH transport, and there is no `ProcessBuilder` anywhere in the production sources.
 * Two unused binaries in a container that reads code nobody controls are two more things an
 * attacker can reach for.
 *
 * **The base is pinned by digest**, for the reason `ScannerImages` gives: a tool that audits
 * everybody else's supply chain cannot pull a floating tag and run whatever comes down.
 */
/**
 * Where the image is published, and what it is called there.
 *
 * **The defaults reproduce the old hardcoded values exactly**, so `jibDockerBuild` with no
 * arguments still produces `vectispire:latest` — the tag `docker-compose.yml` names and the CI
 * smoke job runs. Nothing local changes; what changes is that a release can now aim somewhere
 * that is not the developer's own daemon.
 *
 * Before this, `to { image = "vectispire:latest" }` was a local tag and nothing else: no
 * registry, no digest, no way for anyone to run this software without building it first. An
 * internal deployment meant a JDK, a Gradle cache and a compile on every host.
 *
 *   -PimageNamespace=ghcr.io/asmolabs   the registry and owner; empty means a bare local tag
 *   -PimageTag=0.9.0                    the primary tag
 *   -PimageExtraTags=latest,0.9         additional tags, comma-separated
 */
val imageNamespace = (findProperty("imageNamespace") as String?)?.trim().orEmpty()
val imageName = if (imageNamespace.isEmpty()) "vectispire" else "$imageNamespace/vectispire"
val imageTag = (findProperty("imageTag") as String?)?.trim().takeIf { !it.isNullOrEmpty() } ?: "latest"
val imageExtraTags = (findProperty("imageExtraTags") as String?)
    ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet().orEmpty()

jib {
    from {
        // eclipse-temurin:25-jre-alpine, resolved with
        // `docker buildx imagetools inspect eclipse-temurin:25-jre-alpine`.
        image = "eclipse-temurin@sha256:3137541deb3cac6626b5d9a4a2187bc0d6a34312f858bd2c67dd01e732e6b682"
        platforms {
            platform {
                architecture = "amd64"
                os = "linux"
            }
        }
    }
    to {
        image = "$imageName:$imageTag"
        tags = imageExtraTags
    }
    container {
        ports = listOf("3180")
        // Numeric rather than a name: the base image has no such account, and a UID needs none.
        // It is what keeps the process off root inside a container that launches scanners.
        user = "1000:1000"
        // Fixed, so the same source produces the same image. The default is the epoch for the
        // same reason; naming it here is so nobody "fixes" it to the current time later.
        // **Named, not inferred.** Jib infers the entry point by reading class files with a
        // bundled ASM that does not know class file major 69, so on JDK 25 the build fails
        // with "Unsupported class file major version 69". Naming it skips the scan — and it
        // is one less thing decided by a heuristic.
        mainClass = "com.asmolabs.vectispire.core.VectispireApplication"
        creationTime = "EPOCH"
        jvmFlags = listOf("-XX:MaxRAMPercentage=75")
    }
    extraDirectories {
        // The licence and the notice travel with every copy — Apache-2.0 clause 4 — and the audit
        // mirror's directory has to exist so a named volume mounted over it inherits an owner
        // the runtime user can write to.
        setPaths(listOf(layout.buildDirectory.dir("jib-extra").get().asFile))
        // **1777, and that is a Jib limitation rather than a preference.** Docker initialises a
        // named volume from what it finds at the mount point, ownership included — and Jib can
        // express mode but not ownership, so the directory arrives `root:root` whatever is asked.
        // Left at 755 the unprivileged runtime user cannot write, every audit-mirror append fails
        // on a permission error, and the mirror is configured and absent at once: the outcome
        // worse than having none.
        //
        // The sticky bit would narrow it further, and Jib will not take one — it accepts three
        // octal digits only. What keeps 777 defensible is that a single process runs here, as a
        // single unprivileged user, in a container whose root filesystem it does not own.
        permissions = mapOf("/var/lib/vectispire/audit" to "777")
    }
}

/** Stages what the image carries beyond the application itself. */
val jibExtras = tasks.register<Copy>("jibExtras") {
    from(rootProject.projectDir.parentFile) {
        include("LICENSE", "NOTICE")
        into("app")
    }
    into(layout.buildDirectory.dir("jib-extra"))
    doLast {
        // Created empty: Docker initialises a named volume from what it finds at the mount point,
        // ownership included, so this directory existing is what stops the volume arriving
        // root-owned and every audit-mirror append failing on a permission error.
        layout.buildDirectory.dir("jib-extra/var/lib/vectispire/audit").get().asFile.mkdirs()
    }
}

tasks.matching { it.name.startsWith("jib") && it.name != "jibExtras" }.configureEach {
    dependsOn(jibExtras)
}

/**
 * The control plane's own floor.
 *
 * **Why an aggregate and not one rule per layer.** The four packages below sit at 73% (services),
 * 67% (api), 89% (persistence) and 57% (repositories), and the spread is not a quality gradient:
 * a repository is a handful of query declarations whose real test is the integration campaign,
 * while a service is where the branches live. Four separate floors would encode today's ratios as
 * a target and fail the day somebody moves a method between layers for good reasons.
 *
 * Set just under the measured 71%: a floor catches a regression — a class added with no test, a
 * suite deleted in a hurry — and is not an aspiration. The domain keeps its own, higher bar in
 * `vectispire-common`, because that is the layer argued to be exhaustively testable.
 *
 * **Unit coverage only.** The integration campaign writes its own execution data and is not
 * counted here; folding it in would make this number depend on whether somebody had a Docker
 * daemon, which is the opposite of what a gate should do.
 */
/**
 * The one system property a developer passes through to the test JVM.
 *
 * `-D` on the command line reaches Gradle's own JVM and stops there; a test asking for it sees
 * nothing, which reads as "the flag does not work" rather than as "the flag did not arrive".
 * Forwarded explicitly, and only this one: a blanket copy of every system property would make a
 * test run depend on whatever the developer's environment happens to carry.
 *
 * Used by `ClientContractSpecTest` to rewrite `vectispire-angular/openapi.json` instead of
 * asserting against it.
 */
tasks.named<Test>("test") {
    systemProperty(
        "vectispire.openapi.write",
        providers.systemProperty("vectispire.openapi.write").getOrElse("false"))

    // **Les fichiers que la suite lit hors du module doivent être déclarés, sinon elle ne
    // retourne pas quand ils changent.** `ApiReferenceTest` lit la référence REST et le contrat ;
    // sans ces entrées, Gradle voit la tâche à jour, la saute, et le garde reste vert sur une
    // documentation qu'on vient de casser. Constaté en mutant la doc : le test ne s'est pas
    // exécuté du tout, ce qui se lit exactement comme un succès.
    inputs.files(
        rootProject.file("../docs/en/api/rest_api_reference.md"),
        rootProject.file("../docs/fr/api/rest_api_reference.md"),
        rootProject.file("../vectispire-angular/openapi.json"))
        .withPropertyName("documentsTheSuiteReads")
        .withPathSensitivity(PathSensitivity.RELATIVE)

    // Same trap, and the one that would bite hardest: `ExportVersionTest` compares the version in
    // the build, the runtime default, the domain fallback and both npm manifests. A commit
    // touching only `package.json` changes no Java source, so without these the task stays
    // up-to-date and the drift ships — which is precisely the commit this guard exists for.
    inputs.files(
        rootProject.file("gradle.properties"),
        rootProject.file("../package.json"),
        rootProject.file("../vectispire-angular/package.json"))
        .withPropertyName("versionDeclarations")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    classDirectories.setFrom(
        files(classDirectories.files.map {
            // Every package of the control plane but `config` and the application class, by
            // exclusion rather than by list: a list of packages is a list of modules to keep in step,
            // and the one kept while the domains moved out of the layered packages (decisions 0028
            // and 0029) would have dropped each module from the measure as it moved — the figure
            // rising or falling for a reason that has nothing to do with the tests.
            fileTree(it) {
                include("com/asmolabs/vectispire/core/*/**")
                exclude("com/asmolabs/vectispire/core/config/**")
            }
        })
    )
    violationRules {
        rule {
            element = "BUNDLE"
            limit {
                counter = "INSTRUCTION"
                minimum = "0.68".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}

plugins {
    id("zanshin.java-conventions")
    alias(libs.plugins.springBoot)
}

/**
 * The control plane: schema, repositories, use cases, HTTP API, agent protocol.
 *
 * Internally it keeps the layer rule the NestJS tree enforced:
 *
 * ```
 *   api ──► services ──► repositories ──► persistence ──► database
 *              │                              │
 *              └──────────────┬───────────────┘
 *                             ▼
 *                        zanshin-common
 * ```
 *
 * **Only `repositories` may speak SQL.** Not for purity: the behaviour four engines disagree
 * about — locking, upsert, boolean width, timestamp precision — has to sit where a
 * portability suite can reach it, and that is there. A service writing a query fails
 * `ArchitectureTest`.
 *
 * The four drivers are `runtimeOnly`. They must be in the image, and no compiled class may
 * name one: a class importing `org.postgresql` is a class that stopped working on the other
 * three, which is a failure a portability campaign should catch before an operator does.
 */
dependencies {
    implementation(project(":zanshin-common"))
    implementation(platform(libs.spring.boot.bom))
    testImplementation(platform(libs.spring.boot.bom))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation(libs.liquibase.core)
    // Spring Boot 4 split its autoconfigurations into modules: `liquibase-core` alone no longer
    // brings the one that runs the changelog at startup. Without this the application boots,
    // Hibernate validates against an empty database, and the failure reads "missing table".
    implementation(libs.spring.boot.liquibase)

    runtimeOnly(libs.postgresql)
    runtimeOnly(libs.mariadb)
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
    // SQLite on the unit-test classpath, not only at runtime: it is the one engine that needs
    // no daemon, so the changelog can be executed for real in a plain unit test. The other
    // three are the integration campaign's business.
    testRuntimeOnly(libs.sqlite)
    testImplementation(libs.sqlite)
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
    "integrationTestImplementation"("org.testcontainers:testcontainers-mariadb")
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
    systemProperty("zanshin.db.dialect", providers.gradleProperty("dialect").getOrElse("postgres"))
    shouldRunAfter(tasks.test)
}

/**
 * All four engines. A portability defect only shows up by running them all — each of the
 * four has produced one that was invisible on the others.
 */
val engines = listOf("postgres", "mariadb", "mysql", "sqlite")

engines.forEach { engine ->
    tasks.register<Test>("integrationTest${engine.replaceFirstChar { it.uppercase() }}") {
        description = "Runs the campaign against $engine."
        group = "verification"
        testClassesDirs = integrationTest.output.classesDirs
        classpath = configurations["integrationTestRuntimeClasspath"] +
            integrationTest.output +
            sourceSets.main.get().output
        maxParallelForks = 1
        systemProperty("zanshin.db.dialect", engine)
        // Each engine gets its own results directory: one shared directory means the last run
        // overwrites the others, and "which engine failed" stops being answerable.
        reports.junitXml.outputLocation = layout.buildDirectory.dir("test-results/integrationTest-$engine")
        reports.html.outputLocation = layout.buildDirectory.dir("reports/tests/integrationTest-$engine")
    }
}

tasks.register("integrationTestAll") {
    description = "Runs the campaign on all four engines."
    group = "verification"
    dependsOn(engines.map { "integrationTest${it.replaceFirstChar { c -> c.uppercase() }}" })
}

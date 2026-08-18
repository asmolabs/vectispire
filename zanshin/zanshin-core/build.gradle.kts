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
    implementation(libs.bcrypt)

    runtimeOnly(libs.postgresql)
    runtimeOnly(libs.mariadb)
    runtimeOnly(libs.mysql)
    runtimeOnly(libs.sqlite)

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit.junit5)
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
    "integrationTestImplementation"(platform(libs.testcontainers.bom))
    "integrationTestImplementation"("org.testcontainers:junit-jupiter")
    "integrationTestImplementation"("org.testcontainers:postgresql")
    "integrationTestImplementation"("org.testcontainers:mysql")
    "integrationTestImplementation"("org.testcontainers:mariadb")
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
tasks.register("integrationTestAll") {
    description = "Runs the campaign on postgres, mariadb, mysql and sqlite."
    group = "verification"
    dependsOn(integrationTestTask)
    doLast {
        logger.lifecycle("Single engine: -Pdialect=<postgres|mariadb|mysql|sqlite>")
    }
}

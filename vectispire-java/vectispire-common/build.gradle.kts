plugins { id("vectispire.java-conventions") }

/**
 * What the control plane and the agent must agree on.
 *
 * Two things live here. **The calculations that decide** — an issue's fingerprint, the gate
 * verdict, the audit integrity chain, the three export formats — and **scan execution**, the
 * process and filesystem work that turns a checkout into artifacts.
 *
 * They are together because both sides need both: the agent computes fingerprints for the
 * findings it reports, and the control plane runs the same scanners in its built-in worker.
 * Two copies of the fingerprint rule would be two answers to "is this the same issue", which
 * is the one question this system may not get wrong twice.
 *
 * **No Spring, no JPA, no driver.** Not tidiness: the domain half must stay exhaustively
 * testable without a database, because its errors raise no exception — they silently destroy
 * triage. And the scanning half must stay runnable on an agent that has a Docker socket and
 * a temp directory and nothing else.
 *
 * Jackson is the one concession, for the JSON the external scanners emit and the protocol
 * carries. Adding a second line to this block should be the hardest review decision in the
 * repository.
 */
dependencies {
    implementation(platform(libs.spring.boot.bom))
    // `api`, not `implementation`: `ScanArtifacts` hands out a `JsonNode`, so Jackson is part
    // of this module's surface whether or not it is declared as such. Hiding it only means
    // every consumer has to redeclare it and discover why by a compile error.
    api("com.fasterxml.jackson.core:jackson-databind")
    // Jackson 2's time module, and `api` for the same reason: an `Instant` crossing the wire is
    // part of this module's surface. Spring Boot 4 auto-configures Jackson **3**, so nothing
    // registers this for us — see `CoreConfiguration.objectMapper`.
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation(libs.bouncycastle)

    // The Docker daemon API, for the scanning half. It reaches the agent too, which is
    // correct — the agent is what runs the containers. It does *not* reach the domain: the
    // architecture suite forbids `domain` from depending on anything, and this is exactly the
    // kind of dependency that would make the calculations untestable without a daemon.
    implementation(libs.docker.java.core)
    // **Raised for named advisories, not for freshness.** docker-java's transport brings
    // Apache's client, and the versions it and the Spring Boot BOM agree on carry fixable High
    // findings that Vectispire's own SBOM scan reports (see `supply-chain` in CI). Declared here
    // rather than excluded: the transport needs them, and Gradle takes the highest of the
    // declared version and the platform's constraint.
    implementation(libs.apache.httpclient5)
    implementation(libs.apache.httpcore5)
    implementation(libs.apache.httpcore5.h2)

    implementation(libs.docker.java.transport)

    // JGit rather than shelling out to the `git` binary. Three reasons, all of them things the
    // subprocess version could not do: the agent's host no longer needs git installed; failures
    // arrive as typed exceptions instead of English-only prose that has to be pattern-matched
    // (the original pinned `LC_ALL=C` for exactly that, and found the need through a test on a
    // French machine); and the deployment key never touches the filesystem.
    implementation(libs.jgit)
    // `bcpkix` alongside `bcprov`, because Apache MINA sshd detects BouncyCastle on the
    // classpath and then requires its PEM reader. A half-present BouncyCastle fails in a
    // static initializer, which surfaces as `ExceptionInInitializerError` from a class nobody
    // named — the least legible way to discover a missing dependency.
    implementation(libs.bouncycastle.pkix)
    implementation(libs.jgit.ssh)

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit.junit5)
    // **Test scope, and one class needs it.** The austerity above is about what ships: this
    // module must stay runnable on an agent with a Docker socket and nothing else, and a test
    // dependency reaches neither the agent nor the control plane. `ScanRunnerTest` asserts that
    // a scanner which fails is *reported* rather than read as a clean target, and the only seam
    // is `ContainerRunner` — a final class, so there is no hand-written fake to write instead.
    // The alternative was the integration campaign, which CI does not run; a guard against
    // silent data loss belongs where it runs on every change.
    testImplementation(platform(libs.spring.boot.bom))
    testImplementation("org.mockito:mockito-core")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}


/**
 * The scanning campaign, kept apart from the unit tests because it needs a Docker daemon.
 *
 * <p>Deliberately not built on Testcontainers. `ContainerRunner` is the thing under test, so
 * running it through Testcontainers would mostly test Testcontainers; what this needs is a real
 * daemon and a tiny image. Testcontainers earns its place in `vectispire-core`, where the four
 * database engines are.
 *
 * **There is no "skip if Docker is missing" guard**, for the reason that holds everywhere in
 * this repository: a suite that skips itself reports green without checking anything, and these
 * are the only executable proof that `cap_drop`, `network: none` and the memory ceiling reach
 * the daemon at all.
 */
val integrationTest: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations["integrationTestImplementation"].extendsFrom(configurations.testImplementation.get())
configurations["integrationTestRuntimeOnly"].extendsFrom(configurations.testRuntimeOnly.get())

tasks.register<Test>("integrationTest") {
    description = "Runs the scanner containers against a real Docker daemon."
    group = "verification"
    testClassesDirs = integrationTest.output.classesDirs
    classpath = configurations["integrationTestRuntimeClasspath"] + integrationTest.output + sourceSets.main.get().output
    shouldRunAfter(tasks.test)
}

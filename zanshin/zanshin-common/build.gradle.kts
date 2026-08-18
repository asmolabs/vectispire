plugins { id("zanshin.java-conventions") }

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
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation(libs.bouncycastle)

    // The Docker daemon API, for the scanning half. It reaches the agent too, which is
    // correct — the agent is what runs the containers. It does *not* reach the domain: the
    // architecture suite forbids `domain` from depending on anything, and this is exactly the
    // kind of dependency that would make the calculations untestable without a daemon.
    implementation(libs.docker.java.core)
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
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}


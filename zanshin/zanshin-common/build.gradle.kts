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

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit.junit5)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

/**
 * The golden vectors are read from the NestJS tree, not copied into this one.
 *
 * They were generated from the Python implementation and are what proves the fingerprint and
 * the gate verdict survived two ports unchanged. A copy would be a second file that can drift
 * from the first, and the drift would be invisible: both suites would stay green while the two
 * backends disagreed about which issue is which.
 */
sourceSets.test {
    resources.srcDir(rootProject.layout.projectDirectory.dir("../backend/test/vectors"))
}

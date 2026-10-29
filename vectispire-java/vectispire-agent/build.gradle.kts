plugins {
    id("vectispire.java-conventions")
    alias(libs.plugins.springBoot)
    alias(libs.plugins.jib)
}

/**
 * The remote agent: it long-polls the control plane for work, runs the scanners, posts the
 * results back.
 *
 * **Read this list for what is absent.** No `vectispire-core`, no driver, no Spring Data, no
 * `-web` starter. This is the module where a well-meant "it would be handy if the agent could
 * look up its own targets" gets introduced, and it cannot be, because there is nothing here
 * to look them up with (decision 0003).
 *
 * The plain `spring-boot-starter`: configuration binding, logging, lifecycle. HTTP goes
 * through the JDK's own client, which has the two things long polling needs — a request
 * timeout and a redirect policy — and nothing else.
 */
dependencies {
    implementation(project(":vectispire-common"))
    implementation(platform(libs.spring.boot.bom))
    testImplementation(platform(libs.spring.boot.bom))
    implementation("org.springframework.boot:spring-boot-starter")
    // The Kubernetes executor's mounts cross into a scan pod as tar archives (decision 0045 §4).
    implementation(libs.commons.compress)

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit.junit5)
    // The Kubernetes executor's tests run a real cluster, k3s, in a container (`kubernetesTest`).
    testImplementation("org.testcontainers:testcontainers")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

/**
 * A stable jar name, because four other files already assume one.
 *
 * `gradle.properties` sets a project version, so `bootJar` produced `vectispire-agent-0.9.0.jar`
 * while `Dockerfile`, `Dockerfile.agent`, `release.yml` and the nightly workflow all copy
 * `vectispire-agent.jar`. Every one of those steps failed on a file that never existed — and nothing
 * noticed, because no CI job builds the images or runs a release.
 *
 * Pinned here rather than by teaching four callers to glob a version they do not care about:
 * the version belongs in the manifest and in the release artifact's name, which `release.yml`
 * applies itself when it renames the file.
 */
/**
 * A floor on the module that runs on machines this deployment does not own.
 *
 * **It was the only module without one, which is the wrong way round.** `vectispire-common`
 * carries two floors and `vectispire-core` one; the agent — which holds a bearer token, reaches a
 * control plane over the network, and signs the results it hands back — carried none. The repo
 * argues throughout that a guarantee nothing executes is not a guarantee, and this was the place
 * the argument was not applied to itself.
 *
 * **Set just under where the module stands rather than where it ought to**, for the reason
 * `vectispire-common` gives about its own: a floor above the current figure fails the next honest
 * commit and gets raised until nobody reads it. It stops the number going down; raising it is a
 * separate act, made when the tests that justify it exist.
 *
 * **What is still uncovered, named rather than excluded.** `AgentRunner` — the wiring that reads
 * the configuration and starts the loop — and the Spring Boot entry point. An aggregate absorbs
 * them while the total holds, and naming them here is more useful than an exclusion that would
 * make the figure flatter than the module is.
 */
/**
 * **The Kubernetes client and executor are measured by the suite that runs them.** They need a cluster,
 * which `test` never starts, so this floor leaves them out by name and `kubernetesCoverageVerification`
 * below holds them to one of their own, on `kubernetesTest`. Counting them here would lower this figure
 * with code no test of this suite could reach; counting them nowhere would leave them with no floor.
 */
val clusterBound = listOf(
    "com/asmolabs/vectispire/agent/kubernetes/KubernetesApi*",
    "com/asmolabs/vectispire/agent/kubernetes/KubernetesExecutor*",
)

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    classDirectories.setFrom(sourceSets["main"].output.classesDirs.asFileTree.matching { exclude(clusterBound) })
    violationRules {
        rule {
            element = "BUNDLE"
            limit {
                counter = "INSTRUCTION"
                minimum = "0.60".toBigDecimal()
            }
            limit {
                // Lower than instruction coverage, and honestly so — same reasoning as the other
                // two modules: a branch is the half of an `if` nobody wrote a case for.
                counter = "BRANCH"
                minimum = "0.45".toBigDecimal()
            }
        }
    }
}

// Part of `check`, so `./gradlew build` enforces it. A verification task nobody runs is a
// preference, not a gate.
tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
}

/**
 * The Kubernetes executor against a real cluster (decision 0045): k3s in a privileged container, the
 * scan namespace under Pod Security `restricted`, the agent's service account holding the chart's Role.
 *
 * **Its own task, not a skip.** `test` excludes the tag because k3s needs a privileged container and a
 * minute to start; this task runs them, needs Docker, and fails without it. CI's `kubernetes` job runs
 * it on every push, on the runner: the `jvm` job's JDK container has no Docker.
 */
tasks.named<Test>("test") {
    useJUnitPlatform { excludeTags("kubernetes") }
}

val kubernetesTest = tasks.register<Test>("kubernetesTest") {
    description = "Runs the Kubernetes executor's tests against k3s in a container."
    group = "verification"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    useJUnitPlatform { includeTags("kubernetes") }
    shouldRunAfter(tasks.named("test"))
}

val kubernetesCoverageVerification = tasks.register<JacocoCoverageVerification>("kubernetesCoverageVerification") {
    description = "Holds the Kubernetes client and executor to a floor measured by kubernetesTest."
    group = "verification"
    executionData(kubernetesTest.map { it.extensions.getByType<JacocoTaskExtension>().destinationFile!! })
    sourceDirectories.setFrom(sourceSets["main"].allSource.srcDirs)
    classDirectories.setFrom(sourceSets["main"].output.classesDirs.asFileTree.matching { include(clusterBound) })
    violationRules {
        rule {
            element = "BUNDLE"
            limit {
                counter = "INSTRUCTION"
                // Just under the 0.74 measured on 2026-10-25, as the other floors: it stops the figure going down.
                minimum = "0.70".toBigDecimal()
            }
        }
    }
}

// Depends on the suite rather than following it: a run filtered to one class would otherwise be held to the
// whole suite's floor. CI's `kubernetes` job calls this task, which runs the suite first.
kubernetesCoverageVerification.configure { dependsOn(kubernetesTest) }

tasks.named<Jar>("bootJar") {
    archiveFileName = "vectispire-agent.jar"
}

/**
 * The agent's image, built the same way and for the same reasons as the control plane's.
 *
 * <p>No `git` or `openssh-client` here either: the agent clones through JGit, and it is the
 * component that runs on somebody else's network — the one where an unused binary matters most.
 * It opens no port, so none is declared.
 */
/** Same three properties as the control plane — see `vectispire-core/build.gradle.kts`. */
val imageNamespace = (findProperty("imageNamespace") as String?)?.trim().orEmpty()
val imageName = if (imageNamespace.isEmpty()) "vectispire-agent" else "$imageNamespace/vectispire-agent"
val imageTag = (findProperty("imageTag") as String?)?.trim().takeIf { !it.isNullOrEmpty() } ?: "latest"
val imageExtraTags = (findProperty("imageExtraTags") as String?)
    ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet().orEmpty()

jib {
    from {
        // eclipse-temurin:25-jre-alpine, pinned by digest like every other image this project runs.
        image = "eclipse-temurin@sha256:b7528962e65d43064d8a8b67ba175367896bc948363ea2d3fcd7f10d34e1f048"
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
        user = "1000:1000"
        // **Named, not inferred.** Jib infers the entry point by reading class files with a
        // bundled ASM that does not know class file major 69, so on JDK 25 the build fails
        // with "Unsupported class file major version 69". Naming it skips the scan — and it
        // is one less thing decided by a heuristic.
        mainClass = "com.asmolabs.vectispire.agent.VectispireAgentApplication"
        creationTime = "EPOCH"
        jvmFlags = listOf("-XX:MaxRAMPercentage=75")
        // A home the JVM falls back to, the account having none — see the control plane's image:
        // same defect ("The known-hosts file could not be prepared: /.ssh" on a plain `docker run`),
        // same cure, and `HOME` rather than a flag so the composition's `-Duser.home` still wins.
        environment = mapOf("HOME" to "/home/vectispire")
    }
    extraDirectories {
        setPaths(listOf(layout.buildDirectory.dir("jib-extra").get().asFile))
        // Root-owned whatever is asked (Jib sets no owner), so writable by all for 1000 to create
        // its `.ssh` in; one process, one user, in a container.
        permissions = mapOf("/home/vectispire" to "777")
    }
}

val jibExtras = tasks.register<Copy>("jibExtras") {
    from(rootProject.projectDir.parentFile) {
        include("LICENSE", "NOTICE")
        into("app")
    }
    into(layout.buildDirectory.dir("jib-extra"))
    doLast {
        layout.buildDirectory.dir("jib-extra/home/vectispire").get().asFile.mkdirs()
    }
}

tasks.matching { it.name.startsWith("jib") && it.name != "jibExtras" }.configureEach {
    dependsOn(jibExtras)
}

/**
 * `META-INF/build-info.properties`, so the agent announces the version it was built as. The agents
 * screen showed "1" for every agent, a configuration default. Without the build time, which would
 * make every build a different jar and a different Jib layer.
 */
springBoot {
    buildInfo {
        excludes = setOf("time")
    }
}

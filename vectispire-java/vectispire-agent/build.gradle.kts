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

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit.junit5)
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
jib {
    from {
        // eclipse-temurin:25-jre-alpine, pinned by digest like every other image this project runs.
        image = "eclipse-temurin@sha256:3137541deb3cac6626b5d9a4a2187bc0d6a34312f858bd2c67dd01e732e6b682"
        platforms {
            platform {
                architecture = "amd64"
                os = "linux"
            }
        }
    }
    to {
        image = "vectispire-agent:latest"
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
    }
    extraDirectories {
        setPaths(listOf(layout.buildDirectory.dir("jib-extra").get().asFile))
    }
}

val jibExtras = tasks.register<Copy>("jibExtras") {
    from(rootProject.projectDir.parentFile) {
        include("LICENSE", "NOTICE")
        into("app")
    }
    into(layout.buildDirectory.dir("jib-extra"))
}

tasks.matching { it.name.startsWith("jib") && it.name != "jibExtras" }.configureEach {
    dependsOn(jibExtras)
}

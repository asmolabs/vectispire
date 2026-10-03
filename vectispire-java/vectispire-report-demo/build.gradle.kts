plugins {
    id("vectispire.java-conventions")
    // **Declared, not applied: the plugin classpath the two images are built with.** Jib alone resolves
    // older Apache parents and `commons-logging` 1.2 than it does beside the Spring Boot plugin, and none
    // of those is in `gradle/verification-metadata.xml`; this plugin's image is built by the same Jib,
    // so it resolves the same artifacts rather than extend the trust file for a demonstration.
    alias(libs.plugins.springBoot) apply false
    alias(libs.plugins.jib)
}

/**
 * The demonstration report plugin (decision 0035 §6): reads a project export, writes `summary.xlsx`.
 *
 * **Read this list for what is absent.** No `vectispire-core`, no `vectispire-common`, no Spring: a
 * plugin knows the export's schema, not the platform, and a demonstration that imported the
 * platform's records would prove nothing about the contract an organisation's own plugin is written
 * against. The workbook is written with the JDK — `java.util.zip` and an XML writer of its own, the
 * approach 0032 §10 took for the checklist — and Jackson reads the input.
 *
 * The tests may reach further than the plugin, and do: `vectispire-common` gives them the house
 * workbook reader (the zip guards and the macro refusal the platform applies to an `.xlsx`) and the
 * schema file the platform publishes, so a fixture this plugin reads is one the schema accepts.
 * Test scope reaches neither the jar nor the image.
 */
dependencies {
    implementation(platform(libs.jackson2.bom))
    implementation("com.fasterxml.jackson.core:jackson-databind")

    testImplementation(platform(libs.junit.bom))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation(libs.assertj.core)
    testImplementation(project(":vectispire-common"))
    testImplementation(platform(libs.jackson3.bom))
    testImplementation(libs.json.schema.validator)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

/**
 * The image, built the way the two others are (`vectispire-core/build.gradle.kts` says why Jib) —
 * with a smaller base, because a renderer needs a JVM and nothing else.
 *
 * **Distroless, not the Alpine JRE the two others use.** They start shells for health checks and
 * carry a home their user writes SSH state to; this one reads one file and writes one, inside the
 * closed shape of 0035 §2 — no network, read-only root, a `noexec` scratch. No shell, no package
 * manager, nothing a compromised renderer could reach for. `nonroot` (65532) is the image's user,
 * though the executor runs it as the run directory's owner anyway (`ContainerRun.runningAs`).
 *
 *   -PimageNamespace=ghcr.io/asmolabs   the registry and owner; empty means a bare local tag
 *   -PimageTag=0.9.0                    the primary tag
 */
val imageNamespace = (findProperty("imageNamespace") as String?)?.trim().orEmpty()
val imageName = if (imageNamespace.isEmpty()) "vectispire-report-demo" else "$imageNamespace/vectispire-report-demo"
val imageTag = (findProperty("imageTag") as String?)?.trim().takeIf { !it.isNullOrEmpty() } ?: "latest"

jib {
    from {
        // gcr.io/distroless/java25-debian13:nonroot, the index digest, resolved with
        // `docker buildx imagetools inspect gcr.io/distroless/java25-debian13:nonroot`. Pinned for the
        // reason `ScannerImages` gives: what renders under the platform's signature is what was reviewed.
        image = "gcr.io/distroless/java25-debian13@sha256:ca60da1345c0f17b6d019049e6749e15f10fd3c0da86dec938d2b4ec565d0629"
        platforms {
            platform {
                architecture = "amd64"
                os = "linux"
            }
        }
    }
    to {
        image = "$imageName:$imageTag"
    }
    container {
        user = "65532:65532"
        // Named, not inferred: Jib's bundled ASM cannot read class file major 69 (see the agent's).
        mainClass = "com.asmolabs.vectispire.reportdemo.ReportDemo"
        // The same source gives the same image; the renderer's own determinism would mean little in
        // an image that changed at every build.
        creationTime = "EPOCH"
        // Serial: one thread renders one document, under the scanner limits' memory. No perf data: the
        // JVM would otherwise write a file into the scratch `/tmp` for nothing.
        jvmFlags = listOf("-XX:+UseSerialGC", "-XX:MaxRAMPercentage=75", "-XX:-UsePerfData")
    }
    extraDirectories {
        setPaths(listOf(layout.buildDirectory.dir("jib-extra").get().asFile))
    }
}

/** The licence and the notice travel with every copy — Apache-2.0 clause 4 — as in the two other images. */
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

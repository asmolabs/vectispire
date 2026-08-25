/**
 * What every Vectispire module agrees on: the JDK, the compiler settings, how tests run.
 *
 * Deliberately free of library versions. Those live in `gradle/libs.versions.toml`, where a
 * reader looking for "which Spring Boot is this" finds one answer rather than two that can
 * drift apart.
 */
plugins {
    `java-library`
    jacoco
}

repositories { mavenCentral() }

java {
    toolchain {
        // Pinned, not inherited from whatever JAVA_HOME happens to be. A build that quietly
        // compiles against a different JDK than the one it is deployed on is the failure
        // this line exists to prevent.
        languageVersion = JavaLanguageVersion.of(25)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // `-parameters` is not cosmetic: Spring resolves handler and constructor parameter
    // names from it, and Jackson binds records without annotations because of it. Without
    // it, binding fails at runtime with a message that names no parameter.
    //
    // The three excluded lint categories are ones Spring and Jackson provoke on our behalf;
    // excluding them is what keeps `-Werror` usable rather than permanently off.
    options.compilerArgs.addAll(listOf("-parameters", "-Xlint:all,-serial,-this-escape,-processing", "-Werror"))
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// XML alongside the HTML: the HTML is for a person looking at one class, the XML is what a
// coverage gate and any external reader can actually parse.
tasks.withType<JacocoReport>().configureEach {
    reports {
        xml.required = true
        html.required = true
    }
}

// **Only the `test` task, deliberately.** `finalizedBy` across every Test task made
// `integrationTest` trigger `jacocoTestReport` too — and that report reads `test.exec`, so
// running the integration campaign alone produced a coverage report describing the *unit* run,
// or a stale one. A coverage number attached to the wrong execution is worse than none.
tasks.named<Test>("test") {
    finalizedBy(tasks.named("jacocoTestReport"))
}

dependencyLocking {
    lockAllConfigurations()
}


plugins {
    id("vectispire.java-conventions")
    alias(libs.plugins.springBoot)
}

/**
 * The remote agent: it long-polls the control plane for work, runs the scanners, posts the
 * results back.
 *
 * **Read this list for what is absent.** No `zanshin-core`, no driver, no Spring Data, no
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

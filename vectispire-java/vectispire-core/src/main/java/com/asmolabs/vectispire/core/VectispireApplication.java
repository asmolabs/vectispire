package com.asmolabs.vectispire.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.modulith.Modulithic;

/**
 * The control plane: administration API, issue lifecycle, scan queue, agent protocol.
 *
 * <p><b>The foundation is declared to Spring Modulith as its shared modules</b> (decision 0028):
 * every domain may use them (decision 0026), which is what a shared module means to Modulith — always
 * an allowed dependency, always bootstrapped with a module under test. They stay closed: their
 * {@code persistence} and {@code internal} packages are hidden like any other module's, and they take
 * part in the cycle check. Declaring them open instead would have published the audit log's
 * repository to every domain — the coupling the move to modules exists to take away. The annotation
 * is metadata: it is read by {@code ApplicationModules}, in {@code ModularityObservationTest}, and by
 * nothing at runtime.
 */
@SpringBootApplication
@Modulithic(sharedModules = {"settings", "outbound", "crypto", "audit", "outbox", "reporting"})
@org.springframework.boot.context.properties.ConfigurationPropertiesScan
@org.springframework.scheduling.annotation.EnableScheduling
public class VectispireApplication {

    public static void main(String[] args) {
        SpringApplication.run(VectispireApplication.class, args);
    }
}

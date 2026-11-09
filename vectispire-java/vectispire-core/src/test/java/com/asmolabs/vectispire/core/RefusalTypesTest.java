package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaConstructorCall;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The control plane refuses a caller with {@code InvalidInputException} and {@code NotFoundException},
 * never with the bare JDK types they extend.
 *
 * <p><b>Why a rule, and not only the handler.</b> Since the handler stopped answering a bare {@code
 * IllegalArgumentException} with 400 and its message, a refusal written with one is a 500: the
 * sentence is logged and the caller told that something broke. Nothing about the line says so — it
 * compiles, it reads right, and the route's own test is the only thing that would notice, if the route
 * has one for that refusal. Most do not: the link-local refusal of a repository URL had none. So each
 * bare one in the control plane is named here with the reason it is not a caller's refusal, and a new
 * one fails until somebody decides which it is.
 */
@DisplayName("the control plane's refusals")
class RefusalTypesTest {

    /** Each is a defect when it fires — what the caller sent was checked before it got there. */
    private static final Set<String> BARE_ON_PURPOSE = Set.of(
            // `SiemSender` hands a webhook endpoint to the HTTP sender; only a syslog one reaches it.
            "com.asmolabs.vectispire.core.siem.internal.SyslogSender");

    @Test
    @DisplayName("no refusal is thrown as a bare IllegalArgumentException or NoSuchElementException")
    void noBareRefusals() {
        JavaClasses classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.asmolabs.vectispire.core");
        assertThat(classes).as("an import that found nothing would make this pass").isNotEmpty();

        Set<String> found = new TreeSet<>();
        for (var owner : classes) {
            for (JavaConstructorCall call : owner.getConstructorCallsFromSelf()) {
                String created = call.getTargetOwner().getFullName();
                boolean bare = created.equals(IllegalArgumentException.class.getName())
                        || created.equals(NoSuchElementException.class.getName());
                String outer = owner.getName().replaceAll("\\$.*", "");
                // javac's own, in the method it writes for a serialisable lambda — a Specification is one.
                boolean generated = call.getOrigin().getName().equals("$deserializeLambda$");
                if (bare && !generated && !BARE_ON_PURPOSE.contains(outer)) {
                    found.add(owner.getName() + " — " + call.getSourceCodeLocation());
                }
            }
        }

        assertThat(found)
                .as("throw InvalidInputException (400) or NotFoundException (404) for a caller's mistake; "
                        + "for a defect, name the class in BARE_ON_PURPOSE with the reason")
                .isEmpty();
    }
}

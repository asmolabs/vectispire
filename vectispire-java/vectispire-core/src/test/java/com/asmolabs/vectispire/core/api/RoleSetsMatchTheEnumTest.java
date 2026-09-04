package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.users.Role;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * L'écran et le serveur nomment les mêmes rôles, ou l'écran propose ce que le serveur refuse.
 *
 * <p><b>Le défaut que ce test ferme.</b> {@link Role} porte les drapeaux et le front en tient une
 * copie, à la main, dans {@code session.store.ts}. La copie a divergé : {@code SUPERUSER} y
 * figurait parmi les rôles qui peuvent agir et parmi ceux dont le triage clôt, alors que l'énum
 * lui refuse les deux depuis la séparation entre gouverner et agir. Le compte d'amorçage voyait
 * donc le bouton « Trier », ouvrait la boîte, la remplissait, et récoltait un 403 à
 * l'enregistrement — exactement l'écran cassé que les gardes de rôle existaient pour supprimer.
 *
 * <p><b>Le défaut ne s'est pas vu pendant quatre jours</b>, parce que rien ne comparait les deux
 * listes : les specs du front vérifiaient la cohérence du front avec lui-même, et les tests Java
 * celle du serveur avec lui-même. Chacun était juste, séparément.
 *
 * <p><b>Pourquoi ici et non dans une spec du front.</b> C'est l'énum qui fait autorité, et elle
 * est ici. Un test côté front devrait recopier les drapeaux pour les comparer — soit une
 * troisième copie à maintenir, et le même défaut d'un cran plus loin.
 */
@DisplayName("les ensembles de rôles de l'écran")
class RoleSetsMatchTheEnumTest {

    /**
     * Le magasin de session du front.
     *
     * <p>Déclaré comme entrée de la tâche `test` dans `build.gradle.kts` : sans cela Gradle
     * considère la tâche à jour quand seul ce fichier change, et rejoue un succès périmé — la
     * leçon de `ShippedRealmTest`, apprise en cassant le fichier et en voyant le vert tenir.
     */
    private static final Path STORE =
            Path.of("../../vectispire-angular/src/app/core/session.store.ts");

    @Test
    @DisplayName("nomment exactement les rôles que l'énum désigne")
    void theyMatch() throws IOException {
        assertThat(STORE).as("le magasin de session doit être lisible d'ici").isReadable();
        String source = Files.readString(STORE);

        assertSet(source, "ADMIN_ROLES", Role::isAdministrative);
        assertSet(source, "SECURITY_LEAD_ROLES", Role::canWriteGovernance);
        assertSet(source, "TRIAGE_APPROVER_ROLES", Role::canApproveTriage);
        assertSet(source, "EFFECT_CAUSING_ROLES", Role::canCauseEffects);
        assertSet(source, "PLATFORM_GOVERNOR_ROLES", Role::governsPlatform);
    }

    private static void assertSet(String source, String constant, Predicate<Role> flag) {
        List<String> expected = Arrays.stream(Role.values())
                .filter(flag)
                .map(Enum::name)
                .sorted()
                .toList();

        assertThat(declared(source, constant))
                .as("%s doit nommer les mêmes rôles que le drapeau correspondant de Role", constant)
                .containsExactlyElementsOf(expected);
    }

    /** Les noms de rôles littéraux d'une constante, dans l'ordre alphabétique pour comparer. */
    private static List<String> declared(String source, String constant) {
        Matcher declaration = Pattern
                .compile("export const " + constant + "\\s*:[^=]+=\\s*\\[([^\\]]*)\\]")
                .matcher(source);
        assertThat(declaration.find())
                .as("%s doit être déclarée dans le magasin de session", constant)
                .isTrue();

        Matcher names = Pattern.compile("'([A-Z_]+)'").matcher(declaration.group(1));
        return names.results().map(result -> result.group(1)).sorted().collect(Collectors.toList());
    }
}

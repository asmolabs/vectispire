package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No two types reachable from a route may share a simple name.
 *
 * <h2>The defect this exists for, which nothing could see</h2>
 *
 * <p><b>springdoc names a schema by the class's simple name.</b> Two unrelated records called
 * {@code Summary} therefore produce <em>one</em> schema, and the last one registered wins. There
 * is no warning: not at compile time, not at generation time, and not in the file — the loser
 * simply is not there, and every route that returns it is documented as returning the winner.
 *
 * <p>It shipped. {@code /api/v1/repositories} was published as returning a user record — username,
 * e-mail, role, {@code mustChangePassword} — because {@code UsersController.Summary} was
 * registered after {@code RepositoriesController.Summary}. Six resource types were documented as
 * something else entirely, and anybody generating a client from the contract got that.
 *
 * <p><b>{@code ClientContractSpecTest} could not catch it and never will.</b> It locks the file
 * byte for byte, which guarantees the stability of whatever was produced; the collision happens
 * before the bytes exist, so there is nothing to compare against.
 *
 * <h2>Why the rule is about reachability and not about the repository</h2>
 *
 * <p>Forty-five simple names are duplicated across {@code main}. Most of them never reach a route —
 * two {@code Request} records in unrelated domain packages collide with nothing, because neither
 * is ever serialised. A rule spanning the whole tree would flag all forty-five, and the answer
 * would be a list of exemptions: the mechanism that turns a check into a formality, and exactly
 * what the i18n script's own note warns against.
 *
 * <p>So the rule walks the graph springdoc walks. It starts at every mapped method's return type
 * and request body, descends through generics, record components and getters, and asserts
 * uniqueness on <em>that</em> set. No exemption list, and no false positive to argue about: every
 * pair it reports is a pair that really produces one schema out of two types.
 *
 * <h2>A ratchet that reached zero</h2>
 *
 * <p>It was written as a ratchet rather than a prohibition — twenty names collided when it landed,
 * and a rule that fails on its first run is a rule somebody disables. {@link #KNOWN} is empty now.
 * The list may only shrink: a new collision fails the build, and so does an entry left behind
 * after its fix, because an inventory nobody prunes stops being a debt and becomes an exemption.
 *
 * <h2>What it does not prove</h2>
 *
 * <p>That the schema is otherwise correct. A type reached only through a field springdoc reads
 * differently — a Jackson annotation, a custom serialiser — could still escape this walk. The rule
 * is a lint whose whole job is that the next collision cannot be introduced silently.
 */
@DisplayName("the OpenAPI schema names")
class SchemaNameCollisionTest {

    private static final String API_PACKAGE = "com.asmolabs.vectispire.core.api";

    private static final String PERSISTENCE_PACKAGE = "com.asmolabs.vectispire.core.persistence";

    /**
     * The collisions that still exist. <b>Empty, and it is meant to stay that way.</b>
     *
     * <p>It held twenty. Nine were a habit — a record named for its place in its controller rather
     * than for its subject, {@code Summary} in seven of them at once. Eleven were two duplicated
     * standard models, OpenVEX and CSAF 2.0, each published on two routes and each free to
     * disagree with itself.
     *
     * <p>An entry here is a defect, never a permission, and the assertions below refuse both
     * directions: a new collision fails, and so does an entry left behind after its fix.
     */
    private static final Set<String> KNOWN = Set.of();

    /** Everything the walk stops at: springdoc renders these inline, never as a named schema. */
    private static final Set<String> OPAQUE_PREFIXES =
            Set.of("java.", "javax.", "jakarta.", "org.springframework.", "com.fasterxml.");

    @Test
    @DisplayName("are unique across every type a route can return")
    void schemaNamesAreUnique() {
        Map<String, Set<Class<?>>> byName = new TreeMap<>();
        reachable(byName);

        Map<String, Set<Class<?>>> colliding = byName.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a, TreeMap::new));

        assertThat(byName)
                .as("the walk found nothing, which means it is broken rather than that the API is empty")
                .isNotEmpty();

        List<String> fresh = colliding.entrySet().stream()
                .filter(entry -> !KNOWN.contains(entry.getKey()))
                .map(entry -> entry.getKey() + " ← "
                        + entry.getValue().stream().map(Class::getName).sorted().collect(Collectors.joining(", ")))
                .toList();

        assertThat(fresh)
                .as("this name now produces one OpenAPI schema out of two different types, and the loser is "
                        + "published as the winner. Rename one of the pair: the simple name is the wire "
                        + "contract, whatever the package says")
                .isEmpty();

        assertThat(KNOWN.stream().filter(name -> !colliding.containsKey(name)).toList())
                .as("these no longer collide — strike them off KNOWN in the same commit. A list nobody "
                        + "prunes stops being a debt and becomes an exemption")
                .isEmpty();
    }

    /**
     * No JPA entity crosses a route, in either direction, however deeply nested.
     *
     * <p>A rule of this codebase since 2026-09-25. Routes returned {@code IssueEntity} directly, and
     * {@code BacklogEntry} and {@code IssueDetail} unwrapped it — which made the table the contract:
     * a column mapped for the pipeline's bookkeeping was published the day it was added, and a lazy
     * association would have been serialized, or thrown, outside any transaction. Services hand back
     * records; this walks the same graph springdoc walks, so an entity reached through a generic, a
     * record component or a getter is caught as surely as one returned outright.
     */
    @Test
    @DisplayName("reach no JPA entity")
    void noEntityCrossesARoute() {
        List<String> entities = reachable(new TreeMap<>()).stream()
                .filter(type -> type.getPackageName().equals(PERSISTENCE_PACKAGE))
                .map(Class::getName)
                .sorted()
                .toList();

        assertThat(entities)
                .as("a route returns or accepts these entities; hand the client a record built by the service")
                .isEmpty();
    }

    private static Set<Class<?>> reachable(Map<String, Set<Class<?>>> byName) {
        Set<Class<?>> visited = new LinkedHashSet<>();
        for (Class<?> controller : controllers()) {
            for (Method method : controller.getDeclaredMethods()) {
                if (!isMapped(method)) {
                    continue;
                }
                walk(method.getGenericReturnType(), visited, byName);
                for (int index = 0; index < method.getParameterCount(); index++) {
                    if (method.getParameters()[index].isAnnotationPresent(RequestBody.class)) {
                        walk(method.getGenericParameterTypes()[index], visited, byName);
                    }
                }
            }
        }
        return visited;
    }

    private static List<Class<?>> controllers() {
        ClassPathScanningCandidateComponentProvider scanner =
                new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));

        List<Class<?>> found = new ArrayList<>();
        for (BeanDefinition definition : scanner.findCandidateComponents(API_PACKAGE)) {
            try {
                found.add(Class.forName(definition.getBeanClassName()));
            } catch (ClassNotFoundException impossible) {
                throw new AssertionError(impossible);
            }
        }
        assertThat(found).as("no controller was scanned, so the rule would pass over nothing").isNotEmpty();
        return found;
    }

    private static boolean isMapped(AnnotatedElement method) {
        return method.getAnnotation(RequestMapping.class) != null
                || java.util.Arrays.stream(method.getAnnotations())
                        .anyMatch(annotation ->
                                annotation.annotationType().isAnnotationPresent(RequestMapping.class));
    }

    /**
     * Descends the way a schema generator does: through generics into the types they carry.
     *
     * <p>{@code ResponseEntity<Page<Issue>>} names no schema of its own and {@code Issue} names
     * one, which is why the walk cannot stop at the outermost class.
     */
    private static void walk(Type type, Set<Class<?>> visited, Map<String, Set<Class<?>>> byName) {
        switch (type) {
            case ParameterizedType parameterized -> {
                walk(parameterized.getRawType(), visited, byName);
                for (Type argument : parameterized.getActualTypeArguments()) {
                    walk(argument, visited, byName);
                }
            }
            case WildcardType wildcard -> {
                for (Type bound : wildcard.getUpperBounds()) {
                    walk(bound, visited, byName);
                }
            }
            case Class<?> raw -> walkClass(raw, visited, byName);
            default -> { }
        }
    }

    private static void walkClass(Class<?> raw, Set<Class<?>> visited, Map<String, Set<Class<?>>> byName) {
        if (raw.isArray()) {
            walkClass(raw.getComponentType(), visited, byName);
            return;
        }
        // An enum is rendered inline as a list of strings, so two enums sharing a name collide
        // with nothing. Primitives and the JDK's own types likewise.
        if (raw.isPrimitive() || raw.isEnum() || raw.getPackageName().isEmpty() || isOpaque(raw)) {
            return;
        }
        if (!visited.add(raw)) {
            return;
        }

        byName.computeIfAbsent(raw.getSimpleName(), name -> new LinkedHashSet<>()).add(raw);

        if (raw.isRecord()) {
            for (var component : raw.getRecordComponents()) {
                walk(component.getGenericType(), visited, byName);
            }
            // Not a return: Jackson serializes a record's own getX() beside its components, so a
            // getter added to a view publishes whatever it returns.
        }
        for (Method getter : raw.getMethods()) {
            if (isGetter(getter)) {
                walk(getter.getGenericReturnType(), visited, byName);
            }
        }
    }

    private static boolean isOpaque(Class<?> raw) {
        return OPAQUE_PREFIXES.stream().anyMatch(prefix -> raw.getName().startsWith(prefix));
    }

    private static boolean isGetter(Method method) {
        if (method.getParameterCount() != 0 || method.getDeclaringClass() == Object.class) {
            return false;
        }
        String name = method.getName();
        return (name.startsWith("get") && name.length() > 3)
                || (name.startsWith("is") && name.length() > 2);
    }
}

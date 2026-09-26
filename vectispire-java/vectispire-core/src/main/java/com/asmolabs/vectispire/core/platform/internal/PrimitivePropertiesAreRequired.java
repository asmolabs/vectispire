package com.asmolabs.vectispire.core.platform.internal;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverter;
import io.swagger.v3.core.converter.ModelConverterContext;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.core.util.RefUtils;
import io.swagger.v3.oas.models.media.Schema;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Iterator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Says, in the document, which properties the server always sends.
 *
 * <h2>Why</h2>
 *
 * <p><b>Not one of the schemas this application publishes carried a {@code required} list.</b>
 * Springdoc derives that list from {@code @Schema(requiredMode = REQUIRED)} or from a Jakarta
 * validation annotation, and the response records here carry neither — so the document described
 * every property of every schema as optional. That is not what the server does, and the gap is not
 * academic: the generated client turns it into {@code field?: T} everywhere, so a screen that reads
 * a field the server always sends has to either guard a case that cannot happen or assert its way
 * past the type. The first Angular area converted to the generated types paid exactly that price.
 *
 * <p>A document that under-describes the server is worse than one that says nothing, because it is
 * read as a statement. This converter makes it say the part that can be <em>proved</em>.
 *
 * <h2>The rule, and why it stops where it does</h2>
 *
 * <p>A property of a primitive type — {@code boolean}, {@code int}, {@code long}, {@code double} —
 * has no absent and no null value. Jackson serialises it on every response, in every branch, with
 * no configuration that could omit it. Marking those required states a fact about the JVM rather
 * than an intention about the API, which is why it is safe to apply to everything at once without
 * reading it. A record says so through its components; a class — the JPA entities this API returns
 * directly — through its primitive-returning getters, and those schemas carried no {@code required}
 * at all until the rule reached them.
 *
 * <p><b>Reference types are deliberately left optional.</b> A {@code String} that is in practice
 * always present is a promise about the code, not about the type, and this converter has no way to
 * tell it from one that is genuinely sometimes null. Those are stated one at a time, by annotating
 * the record — and each such annotation is a decision worth a review, not a sweep. The client says
 * the same thing from its side, per field and visibly, until the annotation exists.
 *
 * @see <a href="file:../../../../../../../../../vectispire-angular/src/app/core/api.models.ts">
 *     {@code api.models.ts}, where the claims this converter cannot make are written down</a>
 */
@Configuration
public class PrimitivePropertiesAreRequired {

    @Bean
    public ModelConverter primitivePropertyRequirements() {
        return new Converter();
    }

    static final class Converter implements ModelConverter {

        @Override
        public Schema<?> resolve(
                AnnotatedType type, ModelConverterContext context, Iterator<ModelConverter> chain) {
            Schema<?> resolved = chain.hasNext() ? chain.next().resolve(type, context, chain) : null;
            if (resolved == null) {
                return null;
            }

            Class<?> raw = rawClass(type);
            if (raw == null) {
                return resolved;
            }

            Schema<?> target = named(resolved, context);
            if (target == null || target.getProperties() == null) {
                return resolved;
            }
            if (raw.isRecord()) {
                markRecordComponents(raw, target);
            } else {
                markPrimitiveGetters(raw, target);
            }
            return resolved;
        }

        private static void markRecordComponents(Class<?> record, Schema<?> target) {
            for (RecordComponent component : record.getRecordComponents()) {
                if (component.getType().isPrimitive()) {
                    mark(target, jsonName(record, component));
                }
            }
        }

        /**
         * The same rule for a class that is not a record — the JPA entities this API serialises
         * directly, whose schemas carried no {@code required} at all while the records around them
         * did.
         *
         * <p>A getter that returns a primitive is the same proof as a primitive record component:
         * the value exists, it is not null, and Jackson writes it. Only public no-argument methods
         * are read, and only their conventional property name, so anything renamed or hidden
         * simply finds no property to mark.
         */
        private static void markPrimitiveGetters(Class<?> type, Schema<?> target) {
            for (Method method : type.getMethods()) {
                if (method.getParameterCount() > 0
                        || !method.getReturnType().isPrimitive()
                        || method.getReturnType() == void.class
                        || method.getDeclaringClass() == Object.class) {
                    continue;
                }
                String property = propertyName(method);
                if (property != null) {
                    mark(target, property);
                }
            }
        }

        /** {@code getFoo} and {@code isFoo} become {@code foo}; anything else is not a getter. */
        private static String propertyName(Method method) {
            String name = method.getName();
            JsonProperty renamed = method.getAnnotation(JsonProperty.class);
            if (renamed != null && !renamed.value().isEmpty()) {
                return renamed.value();
            }
            String stripped;
            if (name.startsWith("get") && name.length() > 3) {
                stripped = name.substring(3);
            } else if (name.startsWith("is") && name.length() > 2 && method.getReturnType() == boolean.class) {
                stripped = name.substring(2);
            } else {
                return null;
            }
            return Character.toLowerCase(stripped.charAt(0)) + stripped.substring(1);
        }

        /**
         * A property is claimed only when the schema has one by that name: a getter that Jackson
         * ignored, renamed or never published finds nothing here and says nothing.
         */
        private static void mark(Schema<?> target, String property) {
            if (target.getProperties().containsKey(property)
                    && (target.getRequired() == null || !target.getRequired().contains(property))) {
                target.addRequiredItem(property);
            }
        }

        private static Class<?> rawClass(AnnotatedType type) {
            if (type == null || type.getType() == null) {
                return null;
            }
            try {
                return Json.mapper().constructType(type.getType()).getRawClass();
            } catch (IllegalArgumentException cannotConstruct) {
                return null;
            }
        }

        /**
         * The schema the properties live on.
         *
         * <p>A named model resolves to a {@code $ref} and the properties sit on the definition the
         * context holds, not on the reference that is returned here. An inline schema is its own
         * definition and is returned directly.
         */
        private static Schema<?> named(Schema<?> resolved, ModelConverterContext context) {
            String ref = resolved.get$ref();
            if (ref == null) {
                return resolved;
            }
            String name = (String) RefUtils.extractSimpleName(ref).getKey();
            return name == null ? null : context.getDefinedModels().get(name);
        }

        /**
         * What the property is called on the wire, which {@code @JsonProperty} may rename.
         *
         * <p><b>Asking the record component alone is not enough.</b> {@code @JsonProperty} does not
         * list {@code RECORD_COMPONENT} among its targets, so javac copies it onto the field, the
         * accessor and the constructor parameter and the component itself reports nothing. Reading
         * only the component is why {@code LoginResponse.mfa_required} — a {@code boolean}, and
         * therefore always sent — was looked up under {@code mfaRequired}, found no such property,
         * and stayed optional while every unrenamed primitive around it was marked.
         */
        private static String jsonName(Class<?> record, RecordComponent component) {
            for (JsonProperty renamed : new JsonProperty[] {
                component.getAnnotation(JsonProperty.class),
                component.getAccessor().getAnnotation(JsonProperty.class),
                field(record, component.getName())
            }) {
                if (renamed != null && !renamed.value().isEmpty()) {
                    return renamed.value();
                }
            }
            return component.getName();
        }

        private static JsonProperty field(Class<?> record, String name) {
            try {
                return record.getDeclaredField(name).getAnnotation(JsonProperty.class);
            } catch (NoSuchFieldException noBackingField) {
                return null;
            }
        }
    }
}

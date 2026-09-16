package com.asmolabs.vectispire.core.api.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverter;
import io.swagger.v3.core.converter.ModelConverterContext;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.core.util.RefUtils;
import io.swagger.v3.oas.models.media.Schema;
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
 * <p>A record component of a primitive type — {@code boolean}, {@code int}, {@code long},
 * {@code double} — has no absent and no null value. Jackson serialises it on every response, in
 * every branch, with no configuration that could omit it. Marking those required states a fact
 * about the JVM rather than an intention about the API, which is why it is safe to apply to every
 * record at once without reading them.
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
public class PrimitiveRecordComponentsAreRequired {

    @Bean
    public ModelConverter primitiveRecordComponentRequirements() {
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
            if (raw == null || !raw.isRecord()) {
                return resolved;
            }

            Schema<?> target = named(resolved, context);
            if (target != null) {
                markPrimitives(raw, target);
            }
            return resolved;
        }

        private static void markPrimitives(Class<?> record, Schema<?> target) {
            if (target.getProperties() == null) {
                return;
            }
            for (RecordComponent component : record.getRecordComponents()) {
                if (!component.getType().isPrimitive()) {
                    continue;
                }
                String property = jsonName(record, component);
                // A component can be hidden from the document, or renamed by something this does
                // not model; only claim what the schema actually has a property for.
                if (target.getProperties().containsKey(property)
                        && (target.getRequired() == null || !target.getRequired().contains(property))) {
                    target.addRequiredItem(property);
                }
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

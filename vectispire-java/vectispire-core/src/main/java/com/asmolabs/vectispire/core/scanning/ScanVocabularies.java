package com.asmolabs.vectispire.core.scanning;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.stereotype.Component;

/**
 * The closed vocabularies of the scan views, enumerated in the OpenAPI document from the types that
 * write them — the {@code ChecklistVocabularies} shape.
 *
 * <p>{@link PluginOutcome#state()} is a string on the wire, so the document said {@code string} and the
 * client restated the three states by hand, with nothing to tell it when the server added one. The
 * tokens come from {@link PluginOutcome.State} rather than from an {@code allowableValues} literal,
 * which would be a second list the enum can drift from.
 *
 * <p><b>A property named here that the document lacks fails the document</b>, rather than enumerating
 * nothing: a renamed component would otherwise quietly turn the union back into {@code string}, and
 * {@code ClientContractSpecTest} would record it as the contract.
 */
@Component
class ScanVocabularies implements OpenApiCustomizer {

    /** Schema, property, the tokens it takes. */
    static Map<String, Map<String, List<String>>> vocabularies() {
        return Map.of("PluginOutcome", Map.of("state",
                Arrays.stream(PluginOutcome.State.values()).map(PluginOutcome.State::wireName).toList()));
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"}) // the document's own map of components is raw
    public void customise(OpenAPI document) {
        Map<String, Schema> schemas = document.getComponents() == null ? null : document.getComponents().getSchemas();
        vocabularies().forEach((name, properties) -> properties.forEach((property, tokens) -> {
            Schema<?> owner = schemas == null ? null : schemas.get(name);
            Schema<?> field = owner == null || owner.getProperties() == null ? null : owner.getProperties().get(property);
            if (field == null) {
                throw new IllegalStateException("The OpenAPI document has no " + name + "." + property
                        + " to enumerate: a scan view was renamed without its vocabulary.");
            }
            ((Schema<Object>) field).setEnum(new ArrayList<>(tokens));
        }));
    }
}

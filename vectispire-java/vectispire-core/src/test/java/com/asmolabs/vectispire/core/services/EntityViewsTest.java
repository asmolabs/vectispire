package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.IssueTicketEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.DisplayName;

/**
 * No JPA entity crosses a route; a record restating its fields does, and a restatement drifts.
 * This fails when an entity gains a getter its view does not carry, so publishing a new column —
 * or deciding not to — is a change somebody makes on purpose.
 */
@DisplayName("views returned by the API")
class EntityViewsTest {

    static java.util.stream.Stream<Arguments> pairs() {
        return java.util.stream.Stream.of(
                Arguments.of(IssueEntity.class, IssueView.class),
                Arguments.of(IssueTicketEntity.class, IssueTicketView.class),
                Arguments.of(AuditLogEntity.class, AuditEntryView.class),
                Arguments.of(ApiContractEntity.class, ApiContractView.class));
    }

    @ParameterizedTest(name = "{1} carries every property of {0}")
    @MethodSource("pairs")
    void aViewCarriesEveryPublishedProperty(Class<?> entity, Class<? extends Record> view) {
        Set<String> published = Arrays.stream(entity.getMethods())
                .filter(method -> method.getDeclaringClass() == entity)
                .filter(method -> method.getParameterCount() == 0 && !Modifier.isStatic(method.getModifiers()))
                .filter(method -> !method.isAnnotationPresent(JsonIgnore.class))
                .map(Method::getName)
                .filter(name -> name.startsWith("get") && name.length() > 3)
                .map(name -> Character.toLowerCase(name.charAt(3)) + name.substring(4))
                .collect(Collectors.toSet());
        Set<String> carried = Arrays.stream(view.getRecordComponents())
                .map(RecordComponent::getName)
                .collect(Collectors.toSet());

        assertThat(carried).containsExactlyInAnyOrderElementsOf(published);
    }
}

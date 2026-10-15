package com.asmolabs.vectispire.core.inventory;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.core.inventory.persistence.ApiContractRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ApiEndpointRepository;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The inventory's side of the endpoint ceiling: the discovery fails past it, and a list that arrives past it
 * anyway — from a remote agent that does not apply it — is read as absent, the previous inventory kept.
 */
@DisplayName("the API inventory's endpoint ceiling")
class ApiInventoryCeilingTest {

    private final ApiEndpointRepository endpoints = mock(ApiEndpointRepository.class);
    private final ApiInventoryService service =
            new ApiInventoryService(endpoints, mock(ApiContractRepository.class), Clock.systemUTC());

    @Test
    @DisplayName("a list past the ceiling neither replaces nor adds to what the repository had")
    void pastTheCeilingTheHalfIsAbsent() {
        service.record(9L, 7L, Optional.of(distinct(ApiEndpoint.MAX_PER_REPOSITORY + 1)), Optional.empty());

        verify(endpoints, never()).deleteByRepositoryIdOrScanId(any(), anyLong());
        verify(endpoints, never()).saveAll(anyIterable());
    }

    @Test
    @DisplayName("a list at the ceiling is recorded")
    void atTheCeilingItIsRecorded() {
        service.record(9L, 7L, Optional.of(distinct(ApiEndpoint.MAX_PER_REPOSITORY)), Optional.empty());

        verify(endpoints).deleteByRepositoryIdOrScanId(7L, 9L);
        verify(endpoints).saveAll(anyIterable());
    }

    private static List<ApiEndpoint> distinct(int count) {
        List<ApiEndpoint> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            list.add(new ApiEndpoint("GET", "/p" + i, false, "NONE", ApiVisibility.UNKNOWN, "a.py", 1, "FASTAPI", null,
                    null, null));
        }
        return list;
    }
}

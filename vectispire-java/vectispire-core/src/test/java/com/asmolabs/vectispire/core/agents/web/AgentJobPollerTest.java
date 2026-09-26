package com.asmolabs.vectispire.core.agents.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.web.context.request.async.DeferredResult;

@DisplayName("the agents' long poll")
class AgentJobPollerTest {

    private final ScanDispatcher dispatcher = mock(ScanDispatcher.class);
    private final TaskScheduler scheduler = mock(TaskScheduler.class);
    private final AtomicReference<Runnable> recheck = new AtomicReference<>();
    private final AgentView agent = com.asmolabs.vectispire.core.agents.internal.AgentViews.of(new AgentEntity());

    @Test
    @DisplayName("a scan claimed after the agent stopped listening goes straight back to the queue")
    void anUndeliveredClaimIsReturned() {
        // The wait can run out, or the agent hang up, between the poller's check and its answer.
        // The scan was then claimed by an agent that never received it, and sat until the lease
        // lapsed — twenty minutes, and an attempt.
        AgentJobPoller poller = poller();
        when(dispatcher.claimForAgent(any(), anyBoolean())).thenReturn(Optional.empty());
        DeferredResult<ResponseEntity<Object>> result = poller.claim(agent, true, Duration.ofSeconds(30));

        when(dispatcher.claimForAgent(any(), anyBoolean())).thenAnswer(call -> {
            // The deadline fires while the claim is being made.
            result.setResult(ResponseEntity.status(HttpStatus.NO_CONTENT).build());
            return Optional.of(new ScanDispatcher.AgentTask(42L, null));
        });
        recheck.get().run();

        verify(dispatcher).returnUndelivered(eq(42L), eq(agent));
    }

    @Test
    @DisplayName("a delivered claim is not returned")
    void aDeliveredClaimStays() {
        AgentJobPoller poller = poller();
        when(dispatcher.claimForAgent(any(), anyBoolean())).thenReturn(Optional.empty());
        DeferredResult<ResponseEntity<Object>> result = poller.claim(agent, true, Duration.ofSeconds(30));

        when(dispatcher.claimForAgent(any(), anyBoolean())).thenReturn(Optional.of(new ScanDispatcher.AgentTask(42L, null)));
        recheck.get().run();

        assertThat(result.getResult()).isNotNull();
        verify(dispatcher, never()).returnUndelivered(any(Long.class), any());
    }

    @Test
    @DisplayName("every answer names the limit the claim was held to, the empty one included")
    void everyAnswerCarriesTheLimit() {
        // The 204 is the answer an agent waiting at its limit receives: if it did not carry the
        // new value, a raised limit would reach the agent only at its next restart.
        AgentEntity row = new AgentEntity();
        row.setMaxConcurrent(3);
        AgentView limited = com.asmolabs.vectispire.core.agents.internal.AgentViews.of(row);
        AgentJobPoller poller = poller();

        when(dispatcher.claimForAgent(any(), anyBoolean())).thenReturn(Optional.empty());
        ResponseEntity<?> none = (ResponseEntity<?>) poller.claim(limited, true, Duration.ZERO).getResult();
        assertThat(none.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(none.getHeaders().getFirst(AgentConcurrency.HEADER)).isEqualTo("3");

        when(dispatcher.claimForAgent(any(), anyBoolean())).thenReturn(Optional.of(new ScanDispatcher.AgentTask(42L, null)));
        ResponseEntity<?> one = (ResponseEntity<?>) poller.claim(limited, true, Duration.ZERO).getResult();
        assertThat(one.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(one.getHeaders().getFirst(AgentConcurrency.HEADER)).isEqualTo("3");
    }

    private AgentJobPoller poller() {
        when(scheduler.schedule(any(Runnable.class), any(Instant.class))).thenAnswer(call -> {
            recheck.set(call.getArgument(0));
            return null;
        });
        return new AgentJobPoller(dispatcher, mock(com.asmolabs.vectispire.core.agents.AgentMetrics.class), scheduler);
    }
}

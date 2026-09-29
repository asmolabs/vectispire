package com.asmolabs.vectispire.core.platform.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.core.checklists.ChecklistConflict;
import java.net.URI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.server.ResponseStatusException;

@DisplayName("the exception handler, below the routes")
class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    @DisplayName("a refusal thrown without a reason still answers a problem with a sentence")
    void aReasonlessRefusalGetsTheStatusPhrase() throws Exception {
        // No route throws one today; the first that does must not bring back the problem without a
        // `detail` that the interface renders as its generic fallback.
        ResponseEntity<Object> answer = handler.handleException(
                new ResponseStatusException(HttpStatus.CONFLICT),
                new ServletWebRequest(new MockHttpServletRequest(), new MockHttpServletResponse()));

        assertThat(answer).isNotNull();
        assertThat(answer.getBody()).isInstanceOfSatisfying(ProblemDetail.class, problem ->
                assertThat(problem.getDetail()).isEqualTo("Conflict."));
    }

    @Test
    @DisplayName("a reason is kept as it was written")
    void aReasonIsTheDetail() throws Exception {
        ResponseEntity<Object> answer = handler.handleException(
                new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials."),
                new ServletWebRequest(new MockHttpServletRequest(), new MockHttpServletResponse()));

        assertThat(answer).isNotNull();
        assertThat(answer.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(((ProblemDetail) answer.getBody()).getDetail()).isEqualTo("Invalid credentials.");
    }

    @Test
    @DisplayName("a conflict naming its cause types the problem by it, and one naming none leaves it about:blank")
    void aConflictIsTypedByItsCauseOnly() {
        ProblemDetail typed = handler.conflict(new ChecklistConflict(ChecklistConflict.Cause.TEMPLATE_CHANGED, "Read it again."));
        assertThat(typed.getType()).isEqualTo(URI.create("urn:vectispire:problem:checklist-template-changed"));
        assertThat(typed.getDetail()).isEqualTo("Read it again.");

        // A client branching on the type must not read a cause into a conflict that states none. No type
        // is set, so none is written: absent is about:blank (RFC 9457 §3.1.1).
        ProblemDetail plain = handler.conflict(new ConflictException("Already there."));
        assertThat(plain.getType()).isNull();
        assertThat(plain.getStatus()).isEqualTo(409);
    }
}

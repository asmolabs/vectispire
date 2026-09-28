package com.asmolabs.vectispire.core.platform.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ErrorReportValve;
import org.apache.coyote.ActionCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * What Tomcat answers when it refuses a request itself, as an RFC 9457 problem.
 *
 * <p><b>What reaches it.</b> A URI Tomcat cannot decode — a lone {@code %}, {@code %zz}, an encoded
 * {@code /} — is refused by the connector before any filter or servlet runs, so neither {@code
 * ApiExceptionHandler} nor the error page ({@link ProblemErrorAttributes}) is asked. Tomcat's own
 * valve answered it with an HTML page; Spring Boot's configuration of that valve already hides the
 * report and the server's version, but the page stayed HTML, the one body a client of this API
 * cannot read a {@code detail} from. Anything else that ends here — a status set with nothing
 * written and no error page to forward to — is answered the same way.
 *
 * <p>Tomcat's order of checks is kept: nothing below 400, nothing once a body has been written,
 * nothing when the error has been reported already or the connection accepts no more output. A
 * 5xx is answered with a reference and logged under it, never with what it was thrown with.
 */
public class ProblemErrorReportValve extends ErrorReportValve {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** Public and without arguments: {@code StandardHost} instantiates its error valve by class name. */
    public ProblemErrorReportValve() {
        setShowReport(false);
        setShowServerInfo(false);
    }

    @Override
    protected void report(Request request, Response response, Throwable throwable) {
        int code = response.getStatus();
        if (code < 400 || response.getContentWritten() > 0 || !response.setErrorReported()) {
            return;
        }
        AtomicBoolean ioAllowed = new AtomicBoolean(false);
        response.getCoyoteResponse().action(ActionCode.IS_IO_ALLOWED, ioAllowed);
        if (!ioAllowed.get()) {
            return;
        }

        HttpStatus status = HttpStatus.resolve(code);
        String path = request.getRequestURI();
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("title", status == null ? "Error" : status.getReasonPhrase());
        problem.put("status", code);
        if (code >= 500) {
            String reference = UnexpectedFailure.record(
                    request.getMethod(),
                    String.valueOf(path),
                    throwable == null ? new IllegalStateException("status " + code + " set by the container") : throwable);
            problem.put("detail", UnexpectedFailure.detail(reference));
            problem.put(UnexpectedFailure.REFERENCE, reference);
        } else if (code == 400) {
            // The container refuses little else on its own, and "Bad Request." tells nobody what to fix.
            problem.put("detail", "The request was refused before it reached the application: its URL could not"
                    + " be decoded (a % must be followed by two hexadecimal digits, and an encoded / is not"
                    + " accepted), or the request was otherwise malformed.");
        } else {
            problem.put("detail", status == null ? "The request was refused." : status.getReasonPhrase() + ".");
        }
        if (path != null) {
            problem.put("instance", path);
        }

        try {
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            Writer writer = response.getReporter();
            if (writer != null) {
                writer.write(JSON.writeValueAsString(problem));
                response.finishResponse();
            }
        } catch (IOException | IllegalStateException unwritable) {
            // The client has gone or the response was committed after all; there is nobody to tell.
        }
    }
}

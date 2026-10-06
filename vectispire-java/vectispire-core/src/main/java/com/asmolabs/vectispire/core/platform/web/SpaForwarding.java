package com.asmolabs.vectispire.core.platform.web;

import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Deep links into the bundled interface.
 *
 * <p><b>Without this, refreshing on `/security` returns 404.</b> The Angular router owns those
 * paths in the browser; the server has never heard of them. Typing one, refreshing, or opening
 * a bookmark is a real request for a path no controller maps — and the SPA that would have
 * handled it is never loaded, because the 404 arrives instead of `index.html`.
 *
 * <p><b>The pattern deliberately excludes anything with a dot.</b> `/**` alone would also
 * swallow a missing `main-ABC123.js`, answering it with the HTML page: the browser then reports
 * a syntax error in a script that is actually a document, and the real cause — one asset that
 * failed to ship — is nowhere in the message. One pattern per depth, none with a dot in its last
 * segment; a filename always has an extension.
 *
 * <p><b>One pattern per depth the interface's routes reach — and a route deeper than the patterns
 * is a 404.</b> There were two, for one and two segments, while {@code projects/:projectId/checklist}
 * and {@code solutions/:solutionId/compliance} have three: refreshing a project's checklist, or
 * opening a link to it, answered "Nothing is served at this path" — clicking through the interface
 * never asked the server, so nobody saw it. {@code SpaForwardingTest} now reads every route of
 * {@code app.routes.ts} and fails when one is not forwarded.
 *
 * <p><b>`/api` is not forwarded, and must never be.</b> An unmapped API path has to stay a 404
 * a client can act on. Turning it into HTML would make every typo in a URL look like a working
 * endpoint returning something unparseable.
 *
 * <p>Present only when the interface was bundled, so a backend-only jar does not advertise
 * routes it cannot serve.
 */
@Configuration
@ConditionalOnResource(resources = "classpath:static/index.html")
public class SpaForwarding implements WebMvcConfigurer {

    /** The paths forwarded to {@code index.html}: one, two and three segments, the first never api, actuator or scim. */
    static final List<String> PATTERNS = List.of(
            "/{path:[^\\.]*}",
            "/{path:^(?!api$|actuator$|scim$).*}/{sub:[^\\.]*}",
            "/{path:^(?!api$|actuator$|scim$).*}/{sub:[^\\.]*}/{leaf:[^\\.]*}");

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        PATTERNS.forEach(pattern -> registry.addViewController(pattern).setViewName("forward:/index.html"));
    }
}

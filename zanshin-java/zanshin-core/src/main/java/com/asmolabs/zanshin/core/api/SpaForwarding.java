package com.asmolabs.zanshin.core.api;

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
 * failed to ship — is nowhere in the message. A single segment pattern plus a
 * two-segment one covers the routes this application has; a filename always has an extension.
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

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/{path:[^\\.]*}").setViewName("forward:/index.html");
        registry.addViewController("/{path:^(?!api$|actuator$).*}/{sub:[^\\.]*}")
                .setViewName("forward:/index.html");
    }
}

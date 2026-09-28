package com.asmolabs.vectispire.core.platform.web;

import org.apache.catalina.Container;
import org.apache.catalina.Valve;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.valves.ErrorReportValve;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

/**
 * Puts {@link ProblemErrorReportValve} where Tomcat's error valve was, and nowhere beside it.
 *
 * <p><b>Replaced, not added.</b> Spring Boot adds its own {@code ErrorReportValve} to the host, and
 * two report valves are an order question: the one nearer the end of the pipeline reports first, and
 * the other finds the error reported. So Boot's is removed from the host, and this one is named as
 * the host's error valve class: at start, a host that finds no valve of that class adds one — it
 * would otherwise have added Tomcat's own, and its HTML page with it.
 *
 * <p>Last of the customizers, so Boot's valve is in the pipeline to be removed.
 */
@Component
class ProblemErrorReportCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory>, Ordered {

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        factory.addContextCustomizers(context -> {
            Container parent = context.getParent();
            if (!(parent instanceof StandardHost host)) {
                return;
            }
            for (Valve valve : host.getPipeline().getValves()) {
                if (valve instanceof ErrorReportValve && !(valve instanceof ProblemErrorReportValve)) {
                    host.getPipeline().removeValve(valve);
                }
            }
            // Instantiated by the host as it starts, in the place its default valve would have taken.
            host.setErrorReportValveClass(ProblemErrorReportValve.class.getName());
        });
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}

package com.asmolabs.vectispire.common.scanning;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URL;
import java.security.GeneralSecurityException;
import org.eclipse.jgit.transport.http.HttpConnection;
import org.eclipse.jgit.transport.http.HttpConnectionFactory;
import org.eclipse.jgit.transport.http.HttpConnectionFactory2;

/**
 * JGit's HTTP connections, with every redirect refused.
 *
 * <p><b>The hole.</b> {@code GitClone} validates the URL and refuses a host that is, or resolves
 * to, a link-local address — and JGit then followed a redirect on the first smart-HTTP request
 * ({@code http.followRedirects} defaults to {@code initial}) to whatever host the answer named. A
 * repository URL anybody may set could therefore walk the clone to {@code 169.254.169.254} or to an
 * internal address that was never checked. Decision 0022 kept the token off that second host; this
 * keeps the request itself off it.
 *
 * <p><b>Why not {@code http.followRedirects=false}.</b> JGit reads that setting from the local
 * repository's configuration when the transport is constructed, and a clone's repository is created
 * by {@code CloneCommand} itself, a moment before the transport, with no hook in between; the only
 * other source is the user's global configuration, which is process-wide. The connection factory,
 * on the other hand, is set per transport through the {@code TransportConfigCallback} the clone
 * already takes, before the first request.
 *
 * <p><b>Why it throws rather than rewriting the status.</b> JGit catches an {@code IOException}
 * from the response and retries with other authentication schemes; a status rewritten to 403 or
 * 404 would say something the server did not. An unchecked {@link CloneFailureException} leaves
 * every JGit layer untouched — {@code CloneCommand} cleans up the half-made directory and rethrows —
 * and reaches {@code GitClone.clone}, which rethrows a diagnosed failure as it is.
 */
final class RedirectRefusingConnections implements HttpConnectionFactory2 {

    private final HttpConnectionFactory delegate;

    RedirectRefusingConnections(HttpConnectionFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public HttpConnection create(URL url) throws IOException {
        return refusingRedirects(delegate.create(url));
    }

    @Override
    public HttpConnection create(URL url, java.net.Proxy proxy) throws IOException {
        return refusingRedirects(delegate.create(url, proxy));
    }

    /**
     * The delegate's session, handed the connection it created rather than the wrapper.
     *
     * <p>JGit's own factory configures TLS through its session and expects its own connection type
     * there; passing the wrapper would fail on the first HTTPS request, which is every request here.
     */
    @Override
    public GitSession newSession() {
        GitSession inner = delegate instanceof HttpConnectionFactory2 capable ? capable.newSession() : null;
        return new GitSession() {
            @Override
            public HttpConnection configure(HttpConnection connection, boolean sslVerify)
                    throws IOException, GeneralSecurityException {
                if (inner != null) {
                    inner.configure(unwrap(connection), sslVerify);
                }
                return connection;
            }

            @Override
            public void close() {
                if (inner != null) {
                    inner.close();
                }
            }
        };
    }

    private static HttpConnection refusingRedirects(HttpConnection connection) {
        return (HttpConnection) Proxy.newProxyInstance(
                HttpConnection.class.getClassLoader(),
                new Class<?>[] {HttpConnection.class},
                new Refusing(connection));
    }

    private static HttpConnection unwrap(HttpConnection connection) {
        return Proxy.isProxyClass(connection.getClass())
                        && Proxy.getInvocationHandler(connection) instanceof Refusing refusing
                ? refusing.connection
                : connection;
    }

    /** Delegates every call, and turns a 3xx into a refusal the moment its status is read. */
    private record Refusing(HttpConnection connection) implements InvocationHandler {

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
            Object result;
            try {
                result = method.invoke(connection, args);
            } catch (InvocationTargetException thrown) {
                throw thrown.getCause();
            }
            if ("getResponseCode".equals(method.getName()) && result instanceof Integer status
                    && status >= 300 && status < 400) {
                throw new CloneFailureException(
                        "The repository at " + connection.getURL().getHost() + " answered with a redirect ("
                                + status + ")" + destination(connection.getHeaderField("Location"))
                                + ". A clone follows no redirect, because the host it would reach was never checked: "
                                + "use the address the forge redirects to as the repository URL.",
                        "");
            }
            return result;
        }

        /** The host only: a Location may carry a path or query nobody should find in a log. */
        private static String destination(String location) {
            if (location == null || location.isBlank()) {
                return "";
            }
            try {
                String host = URI.create(location.trim()).getHost();
                return host == null ? "" : " to " + host;
            } catch (IllegalArgumentException unreadable) {
                return "";
            }
        }
    }
}

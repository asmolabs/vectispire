package com.asmolabs.vectispire.common.domain.net;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard.ReservedEndpoint;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The endpoints of Vectispire's own infrastructure, read from the Docker host and the datasource URL.
 *
 * <p><b>Fail closed: a host that cannot be read stops the application.</b> The reservation was read
 * through {@code java.net.URI}, and an address {@code URI} could not parse yielded no reservation, in
 * silence — a Docker proxy named {@code docker_proxy} (an underscore is legal in a container name and
 * not in a URI host), a JDBC URL naming several hosts, {@code jdbc:mysql:replication://…}, or
 * MySQL's {@code address=(host=…)} form. Each was an ordinary deployment in which the guard then let
 * a webhook reach the daemon or the database. A reservation that can vanish is not a reservation;
 * refusing to start names the problem on the first boot, where an operator reads it.
 *
 * <p>So the authorities are read by hand, per vendor, with every host a URL names, and anything this
 * does not know how to read is refused rather than guessed at. A form whose hosts come from DNS
 * ({@code mysql+srv}) is refused for the same reason: the hosts reached are not in the string.
 */
public final class ReservedEndpoints {

    private ReservedEndpoints() {}

    private static final String DOCKER = "the Docker daemon";
    private static final String DATABASE = "the database";

    /**
     * What a {@code DOCKER_HOST} names over the network: nothing for a Unix socket or a named pipe.
     *
     * <p>Without a port both daemon ports are reserved: which one a TLS setup listens on is not in
     * the string, and reserving one too many costs nothing.
     *
     * @throws IllegalArgumentException when the value names a network daemon whose host cannot be read
     */
    public static List<ReservedEndpoint> ofDockerHost(String dockerHost) {
        if (dockerHost == null || dockerHost.isBlank()) {
            return List.of();
        }
        String value = dockerHost.trim();
        int separator = value.indexOf("://");
        String scheme = separator < 0 ? "" : value.substring(0, separator).toLowerCase(Locale.ROOT);
        switch (scheme) {
            case "unix", "npipe" -> {
                return List.of();
            }
            case "tcp", "http", "https" -> {
                String authority = authority(value.substring(separator + 3));
                HostPort endpoint = hostPort(withoutUserInfo(authority), -1, "DOCKER_HOST " + value);
                if (endpoint.port() > 0) {
                    return List.of(new ReservedEndpoint(endpoint.host(), endpoint.port(), DOCKER));
                }
                return List.of(new ReservedEndpoint(endpoint.host(), 2375, DOCKER),
                        new ReservedEndpoint(endpoint.host(), 2376, DOCKER));
            }
            default -> throw new IllegalArgumentException("DOCKER_HOST \"" + value + "\" is not a form Vectispire can "
                    + "read the daemon's address from (unix://, npipe://, tcp://, http:// or https://), so it cannot "
                    + "keep settings from sending requests to the daemon. Correct it, or unset it to use the socket.");
        }
    }

    /**
     * Every host and port a JDBC URL connects to: nothing for a file or in-memory database.
     *
     * <p>For MySQL the X protocol port is reserved beside the classic one on each host: a server
     * started with its defaults listens on {@code 33060} as well, and a request sent there reaches the
     * same data.
     *
     * @throws IllegalArgumentException when the URL connects over the network and its hosts cannot be read
     */
    public static List<ReservedEndpoint> ofDatasource(String jdbcUrl) {
        if (jdbcUrl == null || jdbcUrl.isBlank()) {
            return List.of();
        }
        String value = jdbcUrl.trim();
        String lower = value.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("jdbc:")) {
            throw unreadable(value, "it does not start with jdbc:");
        }
        String rest = value.substring("jdbc:".length());
        String vendor = rest.contains(":") ? rest.substring(0, rest.indexOf(':')).toLowerCase(Locale.ROOT) : "";
        return switch (vendor) {
            case "sqlite" -> List.of();
            case "h2" -> {
                // Embedded, in memory or in a file, unless it names a server.
                String h2 = rest.substring(3).toLowerCase(Locale.ROOT);
                if (h2.startsWith("tcp:") || h2.startsWith("ssl:")) {
                    yield hostList(value, afterSlashes(value, rest.substring(3 + 4)), 9092, List.of());
                }
                yield List.of();
            }
            case "postgresql" -> {
                String after = rest.substring("postgresql:".length());
                // `jdbc:postgresql:database` is the driver's short form for localhost.
                yield after.startsWith("//")
                        ? hostList(value, afterSlashes(value, after), 5432, List.of())
                        : List.of(new ReservedEndpoint("localhost", 5432, DATABASE));
            }
            case "mysql", "mariadb", "mysqlx" -> {
                int slashes = rest.indexOf("//");
                if (slashes < 0) {
                    throw unreadable(value, "it names no host");
                }
                // `mysql:replication:`, `mysql:loadbalance:`, `mariadb:sequential:`… change how the
                // hosts are used, not where they are.
                boolean x = vendor.equals("mysqlx");
                int port = x ? 33060 : 3306;
                List<Integer> alsoReserved = vendor.equals("mysql") && !x ? List.of(33060) : List.of();
                yield hostList(value, afterSlashes(value, rest.substring(slashes)), port, alsoReserved);
            }
            case "mysql+srv", "mysqlx+srv" -> throw unreadable(value,
                    "its hosts are looked up in DNS SRV records and are not in the URL; name the hosts instead");
            default -> throw unreadable(value, "it is not a PostgreSQL, MySQL or MariaDB URL");
        };
    }

    /** The authority of a JDBC URL: what follows {@code //}, up to the path or the parameters. */
    private static String afterSlashes(String url, String fromSlashes) {
        if (!fromSlashes.startsWith("//")) {
            throw unreadable(url, "it names no host");
        }
        String authority = fromSlashes.substring(2);
        int depth = 0;
        for (int index = 0; index < authority.length(); index++) {
            char c = authority.charAt(index);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            } else if (depth == 0 && (c == '/' || c == '?')) {
                return authority.substring(0, index);
            }
        }
        return authority;
    }

    private static List<ReservedEndpoint> hostList(String url, String authority, int defaultPort, List<Integer> alsoReserved) {
        List<ReservedEndpoint> endpoints = new ArrayList<>();
        for (String spec : topLevel(withoutUserInfo(authority))) {
            HostPort endpoint = hostSpec(url, spec.trim(), defaultPort);
            endpoints.add(new ReservedEndpoint(endpoint.host(), endpoint.port(), DATABASE));
            for (int port : alsoReserved) {
                endpoints.add(new ReservedEndpoint(endpoint.host(), port, DATABASE));
            }
        }
        return List.copyOf(endpoints);
    }

    /**
     * One host of a list: {@code host}, {@code host:port}, {@code [v6]:port}, or MySQL's
     * {@code address=(host=h)(port=p)} and {@code (host=h,port=p)}. An empty one is the driver's
     * default, the local machine.
     */
    private static HostPort hostSpec(String url, String spec, int defaultPort) {
        if (spec.isEmpty()) {
            return new HostPort("localhost", defaultPort);
        }
        String lower = spec.toLowerCase(Locale.ROOT);
        if (lower.startsWith("address=") || spec.startsWith("(")) {
            String host = null;
            String port = null;
            for (String pair : spec.substring(lower.startsWith("address=") ? "address=".length() : 0)
                    .replace(")(", ",").replace("(", "").replace(")", "").split(",")) {
                int equals = pair.indexOf('=');
                if (equals < 0) {
                    throw unreadable(url, "\"" + spec + "\" is not a host");
                }
                String key = pair.substring(0, equals).trim().toLowerCase(Locale.ROOT);
                if (key.equals("host")) {
                    host = pair.substring(equals + 1).trim();
                } else if (key.equals("port")) {
                    port = pair.substring(equals + 1).trim();
                }
            }
            String name = host == null || host.isEmpty() ? "localhost" : host.replaceAll("^\\[|]$", "");
            return new HostPort(name, port == null ? defaultPort : port(url, port));
        }
        return hostPort(spec, defaultPort, url);
    }

    private static HostPort hostPort(String spec, int defaultPort, String source) {
        String host;
        String port = null;
        if (spec.startsWith("[")) {
            int close = spec.indexOf(']');
            if (close < 0) {
                throw unreadable(source, "\"" + spec + "\" is not a host");
            }
            host = spec.substring(1, close);
            String tail = spec.substring(close + 1);
            if (tail.startsWith(":")) {
                port = tail.substring(1);
            } else if (!tail.isEmpty()) {
                throw unreadable(source, "\"" + spec + "\" is not a host");
            }
        } else {
            int colon = spec.indexOf(':');
            host = colon < 0 ? spec : spec.substring(0, colon);
            port = colon < 0 ? null : spec.substring(colon + 1);
        }
        if (host.isEmpty() || host.chars().anyMatch(c -> c <= ' ' || c == '/' || c == '@' || c == '(' || c == ')')) {
            throw unreadable(source, "\"" + spec + "\" is not a host");
        }
        return new HostPort(host, port == null || port.isEmpty() ? defaultPort : port(source, port));
    }

    private static int port(String source, String port) {
        try {
            int value = Integer.parseInt(port.trim());
            if (value >= 1 && value <= 65_535) {
                return value;
            }
        } catch (NumberFormatException notANumber) {
            // Refused below, with the value that was not a port.
        }
        throw unreadable(source, "\"" + port + "\" is not a port");
    }

    /** Splits on the commas that separate hosts, not on those inside {@code (host=…,port=…)}. */
    private static List<String> topLevel(String authority) {
        List<String> parts = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int index = 0; index < authority.length(); index++) {
            char c = authority.charAt(index);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            } else if (c == ',' && depth == 0) {
                parts.add(authority.substring(start, index));
                start = index + 1;
            }
        }
        parts.add(authority.substring(start));
        return parts;
    }

    /** The authority of a URL: up to the first {@code /}. */
    private static String authority(String afterScheme) {
        int slash = afterScheme.indexOf('/');
        return slash < 0 ? afterScheme : afterScheme.substring(0, slash);
    }

    /** {@code user:password@} dropped: the last {@code @} outside parentheses ends it. */
    private static String withoutUserInfo(String authority) {
        int depth = 0;
        int at = -1;
        for (int index = 0; index < authority.length(); index++) {
            char c = authority.charAt(index);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            } else if (c == '@' && depth == 0) {
                at = index;
            }
        }
        return at < 0 ? authority : authority.substring(at + 1);
    }

    private static IllegalArgumentException unreadable(String source, String why) {
        // The value itself is not repeated for a datasource URL: it may carry a password.
        String named = source.regionMatches(true, 0, "jdbc:", 0, 5) ? "The datasource URL" : source;
        return new IllegalArgumentException(named + " cannot be read for the hosts it connects to — " + why
                + ". Vectispire refuses to start rather than let settings send requests to its own infrastructure.");
    }

    private record HostPort(String host, int port) {}
}

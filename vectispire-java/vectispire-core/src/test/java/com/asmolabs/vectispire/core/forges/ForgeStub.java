package com.asmolabs.vectispire.core.forges;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;

/**
 * A forge on loopback, over HTTPS, with a certificate from a private CA no trust store holds — the shape of
 * a self-managed GitLab or a GitHub Enterprise Server on an internal network. Only a connection pinning
 * {@link #caPem} reaches it; it answers what each test routes, and records every request with its headers.
 */
public final class ForgeStub implements AutoCloseable {

    /** One routed answer. */
    public record Reply(int status, Map<String, String> headers, String body) {

        public static Reply json(String body) {
            return new Reply(200, Map.of("Content-Type", "application/json"), body);
        }

        public static Reply status(int status) {
            return new Reply(status, Map.of("Content-Type", "application/json"), "{\"message\":\"" + status + "\"}");
        }

        public Reply with(String header, String value) {
            Map<String, String> all = new java.util.LinkedHashMap<>(headers);
            all.put(header, value);
            return new Reply(status, all, body);
        }
    }

    /** One request as received: the path with its query, and the headers by lower-case name. */
    public record Seen(String method, String path, Map<String, String> headers) {}

    public final String caPem;
    public final List<Seen> seen = new CopyOnWriteArrayList<>();
    private final Map<String, Reply> routes = new ConcurrentHashMap<>();
    private final HttpsServer server;

    private ForgeStub(String caPem, HttpsServer server) {
        this.caPem = caPem;
        this.server = server;
    }

    /** Started, with a CA valid from yesterday for a year, and a certificate for the address it listens on. */
    public static ForgeStub start() throws Exception {
        return start(new GeneralName(GeneralName.iPAddress, "127.0.0.1"), new GeneralName(GeneralName.dNSName, "localhost"));
    }

    /**
     * Started on loopback, {@code 127.0.0.1}, with a certificate the same CA issued for {@code otherAddress} alone:
     * a server presenting another host's certificate — trusted, and for the wrong name.
     */
    public static ForgeStub startCertifiedFor(String otherAddress) throws Exception {
        return start(new GeneralName(GeneralName.iPAddress, otherAddress));
    }

    private static ForgeStub start(GeneralName... names) throws Exception {
        KeyPair caKeys = keys();
        X500Name ca = new X500Name("CN=Forge Test CA");
        X509v3CertificateBuilder root = new X509v3CertificateBuilder(ca, BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(Duration.ofDays(1))), Date.from(Instant.now().plus(Duration.ofDays(365))),
                ca, SubjectPublicKeyInfo.getInstance(caKeys.getPublic().getEncoded()));
        root.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        root.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        byte[] caDer = sign(root, caKeys);

        KeyPair leafKeys = keys();
        X509v3CertificateBuilder leaf = new X509v3CertificateBuilder(ca, BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.now().minus(Duration.ofDays(1))), Date.from(Instant.now().plus(Duration.ofDays(30))),
                new X500Name("CN=forge"), SubjectPublicKeyInfo.getInstance(leafKeys.getPublic().getEncoded()));
        leaf.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        byte[] leafDer = sign(leaf, caKeys);

        CertificateFactory x509 = CertificateFactory.getInstance("X.509");
        KeyStore identity = KeyStore.getInstance("PKCS12");
        identity.load(null, null);
        identity.setKeyEntry("forge", leafKeys.getPrivate(), "x".toCharArray(), new X509Certificate[] {
            (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(leafDer)),
            (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(caDer))
        });
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(identity, "x".toCharArray());
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(keyManagers.getKeyManagers(), null, null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        ForgeStub stub = new ForgeStub(pem(caDer), server);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getRawPath()
                    + (exchange.getRequestURI().getRawQuery() == null ? "" : "?" + exchange.getRequestURI().getRawQuery());
            Map<String, String> headers = new java.util.TreeMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(java.util.Locale.ROOT),
                    String.join(",", values)));
            stub.seen.add(new Seen(exchange.getRequestMethod(), path, headers));
            Reply reply = stub.routes.getOrDefault(path, Reply.status(404));
            reply.headers().forEach(exchange.getResponseHeaders()::add);
            byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(reply.status(), bytes.length == 0 ? -1 : bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        return stub;
    }

    public ForgeStub route(String path, Reply reply) {
        routes.put(path, reply);
        return this;
    }

    /** The web address, as an administrator would type it. */
    public String baseUrl() {
        return "https://127.0.0.1:" + server.getAddress().getPort();
    }

    /** A GitLab answering as a healthy instance would for a token with these scopes. */
    public ForgeStub gitlab(String version, String scopesJson, boolean bot) {
        route("/api/v4/personal_access_tokens/self", Reply.json(
                "{\"id\":1,\"name\":\"discovery\",\"active\":true,\"revoked\":false,\"expires_at\":\"2027-01-31\","
                        + "\"scopes\":" + scopesJson + "}"));
        route("/api/v4/version", Reply.json("{\"version\":\"" + version + "\",\"revision\":\"abc\"}"));
        route("/api/v4/user", Reply.json("{\"id\":7,\"username\":\"group_1_bot\",\"bot\":" + bot + "}"));
        return this;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static byte[] sign(X509v3CertificateBuilder builder, KeyPair signer) throws Exception {
        AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
        return builder.build(new BcECContentSignerBuilder(signature, digest)
                        .build(PrivateKeyFactory.createKey(signer.getPrivate().getEncoded())))
                .getEncoded();
    }

    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }
}

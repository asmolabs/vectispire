package com.asmolabs.vectispire.common.domain.net;

import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard.ReservedEndpoint;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * What the outbound guard decides, what the reserved endpoints are read as, and how an address is
 * classified — the Rust control plane's {@code cp-outbound} crate reads it as the reference (see
 * {@code ReferenceSet}).
 *
 * <p>The inputs are the Rust side's lists under {@code vectispire-rust/reference/outbound/}: whoever
 * finds a URL, a datasource URL or an address the two read differently adds it there, and this test
 * writes the answer the Rust side must give. The guard runs with an injected resolver — a fixed table
 * of names and, for anything it does not hold, the literal reading the real resolver does first — so
 * that no answer depends on a DNS server.
 */
class OutboundGuardReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theGuardsDecisions() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("outbound/guard-inputs.json"));
        String label = inputs.get("label").asText();

        Map<String, List<byte[]>> table = new java.util.HashMap<>();
        inputs.get("resolver").properties().forEach(entry -> {
            List<byte[]> addresses = new ArrayList<>();
            entry.getValue().forEach(hex -> addresses.add(HexFormat.of().parseHex(hex.asText())));
            table.put(entry.getKey(), addresses);
        });
        OutboundUrlGuard.HostResolver resolver = hostname -> {
            if (table.containsKey(hostname)) {
                return table.get(hostname);
            }
            return IpAddresses.parseLiteral(hostname).map(List::of).orElse(List.of());
        };

        Map<String, OutboundUrlGuard> guards = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> set : inputs.get("reserved_sets").properties()) {
            List<ReservedEndpoint> reserved = new ArrayList<>();
            set.getValue().forEach(endpoint -> reserved.add(new ReservedEndpoint(
                    endpoint.get("host").asText(), endpoint.get("port").asInt(), endpoint.get("what").asText())));
            guards.put(set.getKey(), new OutboundUrlGuard(resolver, reserved));
        }

        ObjectNode expected = JSON.createObjectNode();
        ArrayNode cases = expected.putArray("urls");
        for (JsonNode input : inputs.get("urls")) {
            String url = input.isNull() ? null : input.asText();
            ObjectNode entry = cases.addObject();
            entry.put("url", url);
            ArrayNode runs = entry.putArray("runs");
            for (OutboundPolicy policy : OutboundPolicy.values()) {
                for (Map.Entry<String, OutboundUrlGuard> guard : guards.entrySet()) {
                    ObjectNode run = runs.addObject();
                    run.put("policy", policy.name());
                    run.put("reserved", guard.getKey());
                    try {
                        record(run, guard.getValue().validateAndResolve(url, policy, label));
                    } catch (UnsafeUrlException refused) {
                        run.put("refused", refused.getMessage());
                    }
                }
            }
        }

        ArrayNode endpoints = expected.putArray("endpoints");
        for (JsonNode input : inputs.get("endpoints")) {
            String host = input.get("host").isNull() ? null : input.get("host").asText();
            int port = input.get("port").asInt();
            ObjectNode entry = endpoints.addObject();
            entry.put("host", host);
            entry.put("port", port);
            ArrayNode runs = entry.putArray("runs");
            for (OutboundPolicy policy : OutboundPolicy.values()) {
                for (Map.Entry<String, OutboundUrlGuard> guard : guards.entrySet()) {
                    ObjectNode run = runs.addObject();
                    run.put("policy", policy.name());
                    run.put("reserved", guard.getKey());
                    try {
                        record(run, guard.getValue().validateAndResolveEndpoint(host, port, policy, label));
                    } catch (UnsafeUrlException refused) {
                        run.put("refused", refused.getMessage());
                    }
                }
            }
        }
        ReferenceSet.expect("outbound/guard-expected.json", JSON.writeValueAsString(expected) + "\n");
    }

    private static void record(ObjectNode run, OutboundUrlGuard.Destination destination) {
        ObjectNode ok = run.putObject("ok");
        ok.put("url", destination.url());
        ok.put("host", destination.host());
        ArrayNode addresses = ok.putArray("addresses");
        destination.addresses().forEach(address -> addresses.add(address.getHostAddress()));
    }

    @Test
    void theReservedEndpointsReading() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("outbound/reserved-inputs.json"));
        ObjectNode expected = JSON.createObjectNode();

        ArrayNode docker = expected.putArray("docker_hosts");
        for (JsonNode input : inputs.get("docker_hosts")) {
            String value = input.isNull() ? null : input.asText();
            ObjectNode entry = docker.addObject();
            entry.put("input", value);
            read(entry, () -> ReservedEndpoints.ofDockerHost(value));
        }
        ArrayNode datasources = expected.putArray("datasources");
        for (JsonNode input : inputs.get("datasources")) {
            String value = input.isNull() ? null : input.asText();
            ObjectNode entry = datasources.addObject();
            entry.put("input", value);
            read(entry, () -> ReservedEndpoints.ofDatasource(value));
        }
        ArrayNode kubernetes = expected.putArray("kubernetes");
        for (JsonNode input : inputs.get("kubernetes")) {
            String host = input.get(0).isNull() ? null : input.get(0).asText();
            String port = input.size() < 2 || input.get(1).isNull() ? null : input.get(1).asText();
            ObjectNode entry = kubernetes.addObject();
            entry.put("host", host);
            entry.put("port", port);
            read(entry, () -> ReservedEndpoints.ofKubernetesService(host, port));
        }
        ReferenceSet.expect("outbound/reserved-expected.json", JSON.writeValueAsString(expected) + "\n");
    }

    private static void read(ObjectNode entry, java.util.function.Supplier<List<ReservedEndpoint>> reading) {
        try {
            ArrayNode endpoints = entry.putArray("endpoints");
            for (ReservedEndpoint endpoint : reading.get()) {
                ObjectNode node = endpoints.addObject();
                node.put("host", endpoint.host());
                node.put("port", endpoint.port());
                node.put("what", endpoint.what());
            }
        } catch (IllegalArgumentException unreadable) {
            entry.remove("endpoints");
            entry.put("error", unreadable.getMessage());
        }
    }

    @Test
    void theAddressClasses() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("outbound/addresses-inputs.json"));
        ArrayNode expected = JSON.createArrayNode();
        for (JsonNode input : inputs) {
            byte[] bytes = HexFormat.of().parseHex(input.asText());
            ObjectNode entry = expected.addObject();
            entry.put("hex", input.asText());
            entry.put("text", textOf(bytes));
            entry.put("link_local", IpAddresses.isLinkLocal(bytes));
            entry.put("metadata", IpAddresses.isMetadata(bytes));
            entry.put("unspecified", IpAddresses.isUnspecified(bytes));
            entry.put("loopback", IpAddresses.isLoopback(bytes));
            entry.put("global", IpAddresses.isGlobal(bytes));
        }
        ReferenceSet.expect("outbound/addresses-expected.json", JSON.writeValueAsString(expected) + "\n");
    }

    private static String textOf(byte[] address) {
        try {
            return InetAddress.getByAddress(address).getHostAddress();
        } catch (UnknownHostException impossible) {
            return HexFormat.of().formatHex(address);
        }
    }
}

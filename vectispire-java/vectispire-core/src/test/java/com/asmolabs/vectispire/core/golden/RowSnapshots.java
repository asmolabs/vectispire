package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.CRC32;

/**
 * The rows a request touched: every table read before and after it, and the difference between the two.
 *
 * <p><b>Every table, not the ones a test names.</b> A test names what it asserts on; what a port gets
 * wrong is the row nobody asserted on — the audit entry, the outbox message, the session's last sight.
 * Reading all of them costs two round trips per request on a connection of the recorder's own (one
 * multi-statement read each), and only when recording.
 *
 * <p><b>Identities are made unambiguous, then ranked.</b> Once per database, the recorder sets each
 * table's {@code auto_increment} to a base of its own ({@link #idBases}), a million apart: a number then
 * says which table it is an id of, wherever it appears — a path, a body, a row — and the golden writes
 * it as that table's rank in the test ({@code «t_repository#1»}, see {@link Placeholders}). Identities
 * still only grow, as they do in production. Reset per test instead, they would be literal, and wrong:
 * a test then rebuilt the previous test's ids, and a cache keyed by a target and stamped by its scans'
 * count and newest id ({@code LicenseGovernanceService}'s tallies) served the previous test's counts.
 */
final class RowSnapshots {

    /** A table holding more than this is compared by count only; nothing in the HTTP suite comes near. */
    static final int ROW_CEILING = 5_000;

    static final long ID_STRIDE = 1_000_000L;
    private static final int FIRST_SLOT = 100;
    private static final int SLOTS = 900;

    private static final Map<String, RowSnapshots> BY_URL = new ConcurrentHashMap<>();

    /** One table: its columns in their declared order, and those of its primary key. */
    record Table(String name, List<String> columns, List<Integer> key, boolean autoIncrement, long idBase) {}

    /** One table's rows, by key, or only their count past the ceiling. */
    record Rows(Map<List<Object>, List<Object>> byKey, long count, boolean overCeiling) {}

    /** Every table's rows at one instant. */
    record Snapshot(Map<String, Rows> tables) {}

    /** A value read from a blob, compared and shown by its length and digest. */
    record Bytes(int length, String sha256) {
        @Override
        public String toString() {
            return "«bytes:" + length + ":" + sha256.substring(0, 16) + "»";
        }
    }

    private final Connection connection;
    private final String snapshotQuery;
    private final List<Table> tables;

    private RowSnapshots(Connection connection) throws SQLException {
        this.connection = connection;
        this.tables = readTables(connection);
        StringBuilder query = new StringBuilder();
        for (Table table : tables) {
            query.append("select * from ").append(table.name()).append(" limit ").append(ROW_CEILING + 1).append(';');
        }
        this.snapshotQuery = query.toString();
        try (Statement statement = connection.createStatement()) {
            // A recorder waiting a year on a metadata lock somebody's open transaction holds is a hung build.
            statement.execute("set session lock_wait_timeout = 10");
            statement.execute("set session information_schema_stats_expiry = 0");
        }
    }

    /** The recorder's connection to the database a context uses: of its own, so a test's pool is never short of one. */
    static RowSnapshots of(String url, String user, String password) {
        return BY_URL.computeIfAbsent(url, key -> {
            try {
                String separator = url.contains("?") ? "&" : "?";
                return new RowSnapshots(DriverManager.getConnection(url + separator + "allowMultiQueries=true", user, password));
            } catch (SQLException failed) {
                throw new IllegalStateException("The traffic recorder could not open " + url, failed);
            }
        });
    }

    List<Table> tables() {
        return tables;
    }

    private boolean placed;

    /**
     * Moves every table's identity counter to its base, once per database: the rows the context's start
     * wrote keep theirs, below every base, and the suite's rows number upward from there.
     *
     * @return the tables whose counter could not be moved, with the reason
     */
    synchronized List<String> placeIdentities() {
        if (placed) {
            return List.of();
        }
        placed = true;
        List<String> refused = new ArrayList<>();
        Map<String, Long> current = nextIdentities();
        for (Table table : tables) {
            if (!table.autoIncrement() || current.getOrDefault(table.name(), 0L) > table.idBase()) {
                continue;
            }
            try (Statement statement = connection.createStatement()) {
                statement.execute("alter table " + table.name() + " auto_increment = " + (table.idBase() + 1));
            } catch (SQLException failed) {
                refused.add(table.name() + ": " + failed.getMessage());
            }
        }
        return refused;
    }

    /** Each table's next identity, as the server holds it now. */
    synchronized Map<String, Long> nextIdentities() {
        Map<String, Long> current = new HashMap<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select table_name, auto_increment from information_schema.tables where table_schema = database()")) {
            while (rows.next()) {
                long next = rows.getLong(2);
                if (!rows.wasNull()) {
                    current.put(rows.getString(1).toLowerCase(), next);
                }
            }
        } catch (SQLException failed) {
            throw new IllegalStateException("The traffic recorder could not read the identity counters", failed);
        }
        return current;
    }

    /** Every table's rows, in one round trip. */
    synchronized Snapshot snapshot() {
        Map<String, Rows> read = new LinkedHashMap<>();
        try (Statement statement = connection.createStatement()) {
            boolean isResult = statement.execute(snapshotQuery);
            for (Table table : tables) {
                if (!isResult) {
                    throw new IllegalStateException("no result for " + table.name());
                }
                try (ResultSet rows = statement.getResultSet()) {
                    read.put(table.name(), rows(table, rows));
                }
                isResult = statement.getMoreResults();
            }
        } catch (SQLException failed) {
            throw new IllegalStateException("The traffic recorder could not read the tables", failed);
        }
        return new Snapshot(read);
    }

    private static Rows rows(Table table, ResultSet rows) throws SQLException {
        ResultSetMetaData meta = rows.getMetaData();
        int width = meta.getColumnCount();
        Map<List<Object>, List<Object>> byKey = new LinkedHashMap<>();
        Map<List<Object>, Integer> duplicates = new HashMap<>();
        long count = 0;
        while (rows.next()) {
            count++;
            if (count > ROW_CEILING) {
                continue;
            }
            List<Object> row = new ArrayList<>(width);
            for (int column = 1; column <= width; column++) {
                row.add(value(rows.getObject(column)));
            }
            List<Object> key;
            if (table.key().isEmpty()) {
                // No primary key: the row is its own key, and a repeated row is told apart by its rank.
                List<Object> whole = new ArrayList<>(row);
                int rank = duplicates.merge(whole, 1, Integer::sum);
                whole.add("#" + rank);
                key = whole;
            } else {
                key = table.key().stream().map(row::get).toList();
            }
            byKey.put(key, Collections.unmodifiableList(row));
        }
        return new Rows(byKey, count, count > ROW_CEILING);
    }

    /** A JDBC value in a form that compares by content and renders the same way on every run. */
    private static Object value(Object raw) {
        return switch (raw) {
            case null -> null;
            case byte[] bytes -> new Bytes(bytes.length, HexFormat.of().formatHex(Digests.sha256(bytes)));
            case java.sql.Timestamp timestamp -> timestamp.toLocalDateTime();
            case java.sql.Date date -> date.toLocalDate();
            case java.sql.Time time -> time.toLocalTime();
            case java.sql.Clob clob -> {
                try {
                    yield clob.getSubString(1, (int) clob.length());
                } catch (SQLException unreadable) {
                    yield "«clob:unreadable»";
                }
            }
            default -> raw;
        };
    }

    /** What changed from one snapshot to the next, as the golden shows it — before normalisation. */
    JsonNode diff(Snapshot before, Snapshot after) {
        ObjectNode changes = JsonNodeFactory.instance.objectNode();
        for (Table table : tables) {
            Rows was = before.tables().get(table.name());
            Rows is = after.tables().get(table.name());
            if (was == null || is == null) {
                continue;
            }
            if (was.overCeiling() || is.overCeiling()) {
                // Read with a limit and no order, the rows past the ceiling are whichever the engine
                // returned first, and their count stops at the limit: nothing about them is comparable.
                changes.putObject(table.name()).put("overCeiling", true);
                continue;
            }
            ArrayNode inserted = JsonNodeFactory.instance.arrayNode();
            ArrayNode updated = JsonNodeFactory.instance.arrayNode();
            ArrayNode deleted = JsonNodeFactory.instance.arrayNode();
            Set<List<Object>> keys = new TreeSet<>(RowSnapshots::compareKeys);
            keys.addAll(was.byKey().keySet());
            keys.addAll(is.byKey().keySet());
            for (List<Object> key : keys) {
                List<Object> old = was.byKey().get(key);
                List<Object> now = is.byKey().get(key);
                if (old == null) {
                    inserted.add(row(table, now));
                } else if (now == null) {
                    deleted.add(row(table, old));
                } else if (!old.equals(now)) {
                    ObjectNode update = JsonNodeFactory.instance.objectNode();
                    ObjectNode keyNode = update.putObject("key");
                    for (int index : table.key()) {
                        keyNode.set(table.columns().get(index), json(now.get(index)));
                    }
                    ObjectNode changed = update.putObject("changed");
                    for (int column = 0; column < table.columns().size(); column++) {
                        if (!Objects.equals(old.get(column), now.get(column))) {
                            ObjectNode change = changed.putObject(table.columns().get(column));
                            change.set("from", json(old.get(column)));
                            change.set("to", json(now.get(column)));
                        }
                    }
                    updated.add(update);
                }
            }
            if (!numericKey(table)) {
                inserted = byMaskedContent(inserted);
                updated = byMaskedContent(updated);
                deleted = byMaskedContent(deleted);
            }
            if (!inserted.isEmpty() || !updated.isEmpty() || !deleted.isEmpty()) {
                ObjectNode tableChanges = JsonNodeFactory.instance.objectNode();
                if (!inserted.isEmpty()) {
                    tableChanges.set("inserted", inserted);
                }
                if (!updated.isEmpty()) {
                    tableChanges.set("updated", updated);
                }
                if (!deleted.isEmpty()) {
                    tableChanges.set("deleted", deleted);
                }
                changes.set(table.name(), tableChanges);
            }
        }
        return changes;
    }

    /** The tables that hold rows, whole: what a test starts from once the harness has emptied the rest. */
    JsonNode dump(Snapshot snapshot) {
        ObjectNode dump = JsonNodeFactory.instance.objectNode();
        for (Table table : tables) {
            Rows rows = snapshot.tables().get(table.name());
            if (rows == null || rows.count() == 0) {
                continue;
            }
            ArrayNode array = JsonNodeFactory.instance.arrayNode();
            Map<List<Object>, List<Object>> sorted = new TreeMap<>(RowSnapshots::compareKeys);
            sorted.putAll(rows.byKey());
            sorted.values().forEach(row -> array.add(row(table, row)));
            dump.set(table.name(), numericKey(table) ? array : byMaskedContent(array));
        }
        return dump;
    }

    /**
     * Whether the table's key is its identity column, which only grows: rows then keep the order they
     * were created in. Any other key — a random UUID, a hash —
     * orders rows by chance, so they are shown in the order of their content with the random parts
     * masked ({@link Placeholders#mask}), the raw key breaking a tie between rows nothing tells apart.
     */
    private static boolean numericKey(Table table) {
        return table.autoIncrement() && table.key().size() == 1;
    }

    private static ArrayNode byMaskedContent(ArrayNode rows) {
        List<JsonNode> list = new ArrayList<>();
        rows.forEach(list::add);
        list.sort(java.util.Comparator.comparing(row -> Placeholders.mask(row.toString())));
        ArrayNode sorted = JsonNodeFactory.instance.arrayNode();
        list.forEach(sorted::add);
        return sorted;
    }

    private static ObjectNode row(Table table, List<Object> values) {
        ObjectNode row = JsonNodeFactory.instance.objectNode();
        for (int column = 0; column < table.columns().size(); column++) {
            row.set(table.columns().get(column), json(values.get(column)));
        }
        return row;
    }

    static JsonNode json(Object value) {
        JsonNodeFactory nodes = JsonNodeFactory.instance;
        return switch (value) {
            case null -> nodes.nullNode();
            case Boolean bool -> nodes.booleanNode(bool);
            case Long number -> nodes.numberNode(number);
            case Integer number -> nodes.numberNode(number);
            case Short number -> nodes.numberNode(number);
            case Byte number -> nodes.numberNode(number);
            case BigInteger number -> nodes.numberNode(number);
            case BigDecimal number -> nodes.numberNode(number);
            case Double number -> nodes.numberNode(number);
            case Float number -> nodes.numberNode(number);
            case LocalDateTime time -> nodes.textNode(time.toString());
            case LocalDate date -> nodes.textNode(date.toString());
            case LocalTime time -> nodes.textNode(time.toString());
            case OffsetDateTime time -> nodes.textNode(time.toString());
            default -> nodes.textNode(value.toString());
        };
    }

    /** Numbers by value, everything else by its text: a key of ids sorts as the ids were issued. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static int compareKeys(List<Object> left, List<Object> right) {
        for (int i = 0; i < Math.min(left.size(), right.size()); i++) {
            Object a = left.get(i);
            Object b = right.get(i);
            int order;
            if (a == null || b == null) {
                order = a == null ? (b == null ? 0 : -1) : 1;
            } else if (a instanceof Number x && b instanceof Number y) {
                order = new BigDecimal(x.toString()).compareTo(new BigDecimal(y.toString()));
            } else if (a instanceof Comparable comparable && a.getClass() == b.getClass()) {
                order = comparable.compareTo(b);
            } else {
                order = a.toString().compareTo(b.toString());
            }
            if (order != 0) {
                return order;
            }
        }
        return Integer.compare(left.size(), right.size());
    }

    private static List<Table> readTables(Connection connection) throws SQLException {
        DatabaseMetaData meta = connection.getMetaData();
        String catalog = connection.getCatalog();
        Set<String> names = new TreeSet<>();
        try (ResultSet found = meta.getTables(catalog, null, "%", new String[] {"TABLE"})) {
            while (found.next()) {
                String name = found.getString("TABLE_NAME").toLowerCase();
                // Flyway's history is the migrations', the same for every test and every replay.
                if (!name.equals("flyway_schema_history")) {
                    names.add(name);
                }
            }
        }
        Map<String, Long> bases = idBases(names);
        List<Table> tables = new ArrayList<>();
        for (String name : names) {
            List<String> columns = new ArrayList<>();
            boolean autoIncrement = false;
            try (ResultSet found = meta.getColumns(catalog, null, name, "%")) {
                Map<Integer, String> byPosition = new TreeMap<>();
                while (found.next()) {
                    byPosition.put(found.getInt("ORDINAL_POSITION"), found.getString("COLUMN_NAME").toLowerCase());
                    autoIncrement |= "YES".equals(found.getString("IS_AUTOINCREMENT"));
                }
                columns.addAll(byPosition.values());
            }
            Map<Short, String> keyColumns = new TreeMap<>();
            try (ResultSet found = meta.getPrimaryKeys(catalog, null, name)) {
                while (found.next()) {
                    keyColumns.put(found.getShort("KEY_SEQ"), found.getString("COLUMN_NAME").toLowerCase());
                }
            }
            List<Integer> key = keyColumns.values().stream().map(columns::indexOf).toList();
            tables.add(new Table(name, List.copyOf(columns), key, autoIncrement, bases.get(name)));
        }
        return List.copyOf(tables);
    }

    /**
     * Each table's identity base: a slot from its name's CRC-32, probed in name order on a collision, so
     * a table keeps its base when another is added unless the newcomer takes its slot first. Nine digits:
     * never an epoch second (ten), nor a clock reading {@link Placeholders} replaces (twelve or more).
     */
    static Map<String, Long> idBases(Set<String> sortedNames) {
        Set<Integer> taken = new HashSet<>();
        Map<String, Long> bases = new LinkedHashMap<>();
        for (String name : sortedNames) {
            CRC32 crc = new CRC32();
            crc.update(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            int slot = (int) (crc.getValue() % SLOTS);
            while (!taken.add(slot)) {
                slot = (slot + 1) % SLOTS;
            }
            bases.put(name, (FIRST_SLOT + slot) * ID_STRIDE);
        }
        return bases;
    }
}

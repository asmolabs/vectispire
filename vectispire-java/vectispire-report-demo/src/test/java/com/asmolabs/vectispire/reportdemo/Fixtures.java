package com.asmolabs.vectispire.reportdemo;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.CellRef;
import com.asmolabs.vectispire.common.domain.checklists.Sheet;
import com.asmolabs.vectispire.common.domain.checklists.Workbook;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.Error;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The exports the demo is tested on, each held to the schema the platform publishes — so a fixture is a
 * document the platform could have produced, and a schema change that one no longer satisfies fails here,
 * where it is cheap, before the core's contract test fails on the real generator.
 */
final class Fixtures {

    static final ObjectMapper JSON = new ObjectMapper();

    /** The ceiling the manifest declares, which the platform reads the output up to. */
    static final long MAX_OUTPUT_BYTES = 20L * 1024 * 1024;

    private Fixtures() {}

    static byte[] export(String name) {
        try (InputStream in = Fixtures.class.getResourceAsStream("/exports/" + name)) {
            assertThat(in).as("fixture %s", name).isNotNull();
            return in.readAllBytes();
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    static ObjectNode tree(String name) {
        try {
            return (ObjectNode) JSON.readTree(export(name));
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    static byte[] bytes(ObjectNode tree) {
        try {
            return JSON.writeValueAsBytes(tree);
        } catch (IOException impossible) {
            throw new UncheckedIOException(impossible);
        }
    }

    /** Fails unless {@code export} is valid against {@code v1.schema.json}, as a draft 2020-12 validator reads it. */
    static void conforms(byte[] export) {
        String schemaText = new String(ProjectExportSchema.of(ProjectExportSchema.MAJOR).orElseThrow(),
                StandardCharsets.UTF_8);
        Schema schema = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
                .getSchema(schemaText, InputFormat.JSON);
        List<Error> errors = schema.validate(new String(export, StandardCharsets.UTF_8), InputFormat.JSON);
        assertThat(errors).as("the fixture against v%d.schema.json", ProjectExportSchema.MAJOR)
                .extracting(error -> error.getInstanceLocation() + ": " + error.getMessage())
                .isEmpty();
    }

    /** The workbook read by the platform's own reader: its zip guards, its content types, its macro refusal. */
    static Workbook read(byte[] xlsx) {
        return Workbook.read(xlsx, MAX_OUTPUT_BYTES);
    }

    static Sheet sheet(Workbook workbook, String name) {
        return workbook.sheet(name).orElseThrow(() -> new AssertionError("no sheet " + name));
    }

    /** The text of a column, by its title in row 1, for each row after it — in order. */
    static List<String> column(Sheet sheet, String title) {
        int column = 0;
        for (Map.Entry<CellRef, ?> heading : sheet.row(1).entrySet()) {
            if (sheet.text(heading.getKey()).equals(title)) {
                column = heading.getKey().column();
            }
        }
        assertThat(column).as("a column titled %s", title).isPositive();
        List<String> values = new ArrayList<>();
        for (int row = 2; row <= sheet.lastRow(); row++) {
            values.add(sheet.text(new CellRef(column, row)));
        }
        return values;
    }

    /** The value beside a label in the first column of the Summary sheet. */
    static String labelled(Sheet sheet, String label) {
        for (int row = 1; row <= sheet.lastRow(); row++) {
            if (sheet.text(new CellRef(1, row)).equals(label)) {
                return sheet.text(new CellRef(2, row));
            }
        }
        throw new AssertionError("no row labelled " + label);
    }
}

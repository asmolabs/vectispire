package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Objects;
import java.util.Optional;

/**
 * What a cell of the workbook holds, as the file states it.
 *
 * <p><b>A formula is a formula.</b> It is read as its expression and the value the last program
 * to save the file cached beside it, and never evaluated (decision 0032 §11): the template's date
 * cell recalculates at every opening, and a product computing it would date the checklist to
 * whenever it was read. The preview shows the expression; the renderer replaces it with a value.
 */
public sealed interface CellValue {

    /** The value as a person reading the sheet sees it; a formula shows its cached result, or nothing. */
    String text();

    /** A string, shared or inline. */
    record Text(String text) implements CellValue {
        public Text {
            Objects.requireNonNull(text, "text");
        }
    }

    /** A number as written in the file — a date too, as the serial the sheet stores. Never parsed. */
    record Number(String literal) implements CellValue {
        public Number {
            Objects.requireNonNull(literal, "literal");
        }

        @Override
        public String text() {
            return literal;
        }
    }

    record Bool(boolean value) implements CellValue {
        @Override
        public String text() {
            return value ? "TRUE" : "FALSE";
        }
    }

    /** An error value the sheet stored, {@code #N/A} or {@code #REF!}. */
    record Error(String code) implements CellValue {
        public Error {
            Objects.requireNonNull(code, "code");
        }

        @Override
        public String text() {
            return code;
        }
    }

    /**
     * @param expression without its leading {@code =}; empty for a cell sharing another's formula,
     *     which the file writes once
     * @param cached the result the saving program stored, when it stored one
     */
    record Formula(String expression, Optional<String> cached) implements CellValue {
        public Formula {
            Objects.requireNonNull(expression, "expression");
            Objects.requireNonNull(cached, "cached");
        }

        @Override
        public String text() {
            return cached.orElse("");
        }
    }
}

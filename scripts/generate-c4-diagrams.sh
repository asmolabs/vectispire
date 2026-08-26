#!/usr/bin/env bash
set -euo pipefail

# Script to generate PNG diagrams from Structurizr C4 DSL (workspace.dsl)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
C4_DIR="${ROOT_DIR}/docs/architecture/c4"
OUTPUT_DIR="${C4_DIR}/diagrams"

echo "==> Generating C4 PlantUML files (c4plantuml format) from workspace.dsl..."
mkdir -p "${OUTPUT_DIR}"

if command -v structurizr-cli &> /dev/null; then
    echo "Using local structurizr-cli..."
    structurizr-cli export -w "${C4_DIR}/workspace.dsl" -f plantuml/c4plantuml -o "${OUTPUT_DIR}"
elif command -v docker &> /dev/null; then
    echo "Using Docker structurizr/structurizr..."
    docker run --rm -v "${ROOT_DIR}:/work" -w /work structurizr/structurizr export -w docs/architecture/c4/workspace.dsl -f plantuml/c4plantuml
    mv "${C4_DIR}"/*.puml "${OUTPUT_DIR}/" 2>/dev/null || true
else
    echo "Error: Neither structurizr-cli nor docker is available." >&2
    exit 1
fi

# **The fingerprint CI compares against.**
#
# Regenerating the diagrams inside a pipeline turned out not to be portable: the Structurizr image
# carries no shell, so it cannot be a GitLab job image, and reaching it through a Docker-in-Docker
# daemon fails on permissions because the copied workspace is root-owned and the tool is not.
#
# So CI checks a weaker thing, and the weakness is worth stating rather than glossing: it verifies
# that the committed diagrams were generated from *this* `workspace.dsl`, which catches the real
# failure — somebody edits the model and forgets to regenerate. It does not catch a hand-edited
# `.puml`, which the diff-based check did. Anybody hand-editing a generated file has already
# decided to; the person who forgets is the one this protects.
sha256() { command -v sha256sum > /dev/null && sha256sum "$1" | cut -d" " -f1 || shasum -a 256 "$1" | cut -d" " -f1; }
sha256 "${C4_DIR}/workspace.dsl" > "${OUTPUT_DIR}/.workspace.sha256"
echo "==> Recorded the model fingerprint in ${OUTPUT_DIR}/.workspace.sha256"

echo "==> Rendering PNG diagrams from PlantUML files..."
if command -v plantuml &> /dev/null; then
    plantuml -tpng "${OUTPUT_DIR}"/*.puml
elif command -v docker &> /dev/null; then
    docker run --rm -v "${OUTPUT_DIR}:/work" plantuml/plantuml -tpng /work/structurizr-SystemContext.puml /work/structurizr-Containers.puml /work/structurizr-Components.puml
    mv "${C4_DIR}"/*.png "${OUTPUT_DIR}/" 2>/dev/null || true
fi

echo "==> C4 PNG diagrams generated in ${OUTPUT_DIR}:"
ls -la "${OUTPUT_DIR}"/*.png 2>/dev/null || true

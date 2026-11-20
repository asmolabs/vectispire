#!/usr/bin/env python3
"""The tests of third-party-licences.py — what decides which crates' licences ship in the agent's image, and the
checks of NOTICE and LICENSE. Run by check.sh; mutation-checked by security/mutants/agent-compose-dropin.py.

A missing attribution is a defect nobody sees: the image builds, runs and scans the same without it. These pin
the guards on fixtures — a fake `cargo metadata` and crates written to a temporary directory — and the last test
runs the check on the real workspace.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("third_party_licences", os.path.join(HERE, "third-party-licences.py"))
tpl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpl)


class Graph:
    """A fake `cargo metadata`: crates written to a temporary directory, and the edges between them."""

    def __init__(self, root):
        self.root = root
        self.packages = [{"id": "agent", "name": tpl.ROOT_PACKAGE, "version": "2.0.0", "source": None,
                          "license": "Apache-2.0", "manifest_path": os.path.join(root, "agent", "Cargo.toml")}]
        self.deps = {"agent": []}

    def crate(self, name, licence="MIT", files=("LICENSE-MIT",), extra=None):
        directory = os.path.join(self.root, name)
        os.makedirs(directory, exist_ok=True)
        for file in files:
            with open(os.path.join(directory, file), "w") as f:
                f.write(f"{name}: the text of {file}\r\n")
        for relative, text in (extra or {}).items():
            os.makedirs(os.path.dirname(os.path.join(directory, relative)), exist_ok=True)
            with open(os.path.join(directory, relative), "w") as f:
                f.write(text)
        self.packages.append({"id": name, "name": name, "version": "1.0.0", "source": "registry", "license": licence,
                              "manifest_path": os.path.join(directory, "Cargo.toml")})
        self.deps.setdefault(name, [])
        return self

    def edge(self, start, end, kind=None):
        self.deps.setdefault(start, []).append({"pkg": end, "dep_kinds": [{"kind": kind, "target": None}]})
        return self

    def meta(self):
        return {"packages": self.packages, "resolve": {"nodes": [{"id": i, "deps": d} for i, d in self.deps.items()]}}


def names(entries):
    return [entry[0] for entry in entries]


class Linked(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.graph = Graph(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_normal_dependencies_are_followed_transitively_and_the_workspace_is_left_out(self):
        self.graph.crate("a").crate("b").edge("agent", "a").edge("a", "b")
        self.assertEqual(names(tpl.collect([self.graph.meta()])), ["a", "b"])

    def test_a_build_or_dev_dependency_is_not_shipped(self):
        self.graph.crate("cc").crate("criterion").edge("agent", "cc", "build").edge("agent", "criterion", "dev")
        self.assertEqual(names(tpl.collect([self.graph.meta()])), [])

    def test_a_bundled_c_library_built_by_a_build_dependency_is_shipped_with_its_own_licence(self):
        self.graph.crate("openssl-sys").crate("openssl-src", extra={"openssl/LICENSE.txt": "OpenSSL's licence"})
        self.graph.edge("agent", "openssl-sys").edge("openssl-sys", "openssl-src", "build")
        entries = tpl.collect([self.graph.meta()])
        self.assertEqual(names(entries), ["openssl-src", "openssl-sys"])
        labels = [label for label, _ in entries[0][3]]
        self.assertIn("openssl/LICENSE.txt — OpenSSL, bundled and linked: Apache-2.0", labels)
        self.assertIn("OpenSSL's licence\n", [text for _, text in entries[0][3]])

    def test_a_bundled_licence_that_moved_stops_the_generation(self):
        self.graph.crate("libgit2-sys").edge("agent", "libgit2-sys")
        with self.assertRaises(SystemExit) as stopped:
            tpl.collect([self.graph.meta()])
        self.assertIn("libgit2/COPYING", str(stopped.exception.code))

    def test_the_platforms_are_a_union(self):
        amd64 = Graph(self.dir.name).crate("only-amd64").edge("agent", "only-amd64")
        arm64 = Graph(self.dir.name).crate("only-arm64").edge("agent", "only-arm64")
        self.assertEqual(names(tpl.collect([amd64.meta(), arm64.meta()])), ["only-amd64", "only-arm64"])

    def test_every_licence_file_a_crate_ships_is_kept_whatever_the_expression_chooses(self):
        self.graph.crate("both", "MIT OR Apache-2.0", ("LICENSE-APACHE", "LICENSE-MIT", "COPYING", "README.md"))
        self.graph.edge("agent", "both")
        entry = tpl.collect([self.graph.meta()])[0]
        self.assertEqual([label for label, _ in entry[3]], ["COPYING", "LICENSE-APACHE", "LICENSE-MIT"])
        self.assertEqual(entry[3][0][1], "both: the text of COPYING\n", "CRLF read as LF")

    def test_a_crate_without_a_licence_file_is_said_to_have_none(self):
        self.graph.crate("bare", "Apache-2.0", ()).edge("agent", "bare")
        rendered = tpl.render(tpl.collect([self.graph.meta()]))
        self.assertIn("bare 1.0.0 — Apache-2.0\n    ships no licence file", rendered)

    def test_a_text_shared_by_crates_is_printed_once_with_every_crate_that_ships_it(self):
        for name in ("x", "y"):
            self.graph.crate(name, files=(), extra={"LICENSE": "the same text\n"}).edge("agent", name)
        rendered = tpl.render(tpl.collect([self.graph.meta()]))
        self.assertEqual(rendered.count("the same text"), 1)
        self.assertIn("    x 1.0.0: LICENSE\n    y 1.0.0: LICENSE\n", rendered)


class Notice(unittest.TestCase):
    ROOT_NOTICE = "Vectispire\nCopyright 2026 Someone\n\n-----\nThe Java images\n"
    ENTRIES = [("a", "1", "MIT OR Apache-2.0", []), ("b", "1", "Unicode-3.0", [])]
    LIBRARIES = " ".join(library for library, _, _ in tpl.BUNDLED.values())

    def problems(self, notice, licence=b"L", entries=None):
        return tpl.check_notice(entries or self.ENTRIES, notice, licence, self.ROOT_NOTICE, b"L")

    def test_a_notice_naming_every_licence_and_library_passes(self):
        notice = "Vectispire\nCopyright 2026 Someone\n\nMIT, Apache-2.0, Unicode-3.0; " + self.LIBRARIES
        self.assertEqual(self.problems(notice), [])

    def test_a_licence_of_the_graph_the_notice_does_not_name_fails(self):
        notice = "Vectispire\nCopyright 2026 Someone\n\nMIT, Apache-2.0; " + self.LIBRARIES
        self.assertEqual(self.problems(notice), ["vectispire-rust/NOTICE does not name Unicode-3.0, which the binary carries"])

    def test_a_bundled_library_the_notice_does_not_name_fails(self):
        notice = "Vectispire\nCopyright 2026 Someone\n\nMIT, Apache-2.0, Unicode-3.0; libssh2 zlib OpenSSL"
        self.assertEqual(self.problems(notice), ["vectispire-rust/NOTICE does not name libgit2, which the binary carries"])

    def test_a_licence_named_only_inside_a_longer_one_is_not_named(self):
        notice = "Vectispire\nCopyright 2026 Someone\n\nMIT-0, Apache-2.0, Unicode-3.0.1; " + self.LIBRARIES
        self.assertEqual(self.problems(notice), [
            "vectispire-rust/NOTICE does not name MIT, which the binary carries",
            "vectispire-rust/NOTICE does not name Unicode-3.0, which the binary carries",
        ])

    def test_the_old_slash_spelling_is_read_as_a_choice(self):
        self.assertEqual(tpl.spdx_ids("MIT/Apache-2.0"), {"MIT", "Apache-2.0"})
        self.assertEqual(tpl.spdx_ids("(MIT OR Apache-2.0) AND Unicode-3.0 WITH LLVM-exception"),
                         {"MIT", "Apache-2.0", "Unicode-3.0", "LLVM-exception"})

    def test_a_notice_without_the_repository_copyright_fails(self):
        notice = "Vectispire\nCopyright 2026 Someone else\n\nMIT, Apache-2.0, Unicode-3.0; " + self.LIBRARIES
        self.assertEqual(self.problems(notice),
                         ["vectispire-rust/NOTICE does not open with the repository NOTICE's copyright paragraph"])

    def test_a_licence_file_that_is_not_the_repository_one_fails(self):
        notice = "Vectispire\nCopyright 2026 Someone\n\nMIT, Apache-2.0, Unicode-3.0; " + self.LIBRARIES
        self.assertEqual(self.problems(notice, licence=b"L\n"),
                         ["vectispire-rust/LICENSE is not the repository's LICENSE: copy it again"])


class TheWorkspace(unittest.TestCase):
    def test_the_committed_files_are_current(self):
        checked = subprocess.run([sys.executable, os.path.join(HERE, "third-party-licences.py"), "--check"],
                                 capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_a_stale_list_fails_the_check(self):
        with tempfile.TemporaryDirectory() as directory:
            stale = os.path.join(directory, "THIRD-PARTY-LICENSES")
            with open(stale, "w") as f:
                f.write("a list from before the last dependency moved\n")
            output, argv = tpl.OUTPUT, sys.argv
            tpl.OUTPUT, sys.argv = stale, ["third-party-licences.py", "--check"]
            try:
                with self.assertRaises(SystemExit) as stopped:
                    tpl.main()
            finally:
                tpl.OUTPUT, sys.argv = output, argv
            self.assertEqual(stopped.exception.code, 1)
            with open(stale) as f:
                self.assertEqual(f.read(), "a list from before the last dependency moved\n", "--check writes nothing")


if __name__ == "__main__":
    unittest.main(verbosity=1)

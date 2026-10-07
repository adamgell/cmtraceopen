import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from appimage_abi import elf_files, jammy_origins, package_record, read_elf, resolve_tree, select_artifact, squashfs_offset, validate_closure, validate_imports, validate_launchers


def fixture_elf(*, version="GLIBC_2.35", weak=False, machine=62, runpath=None):
    """Owned ELF64 bytes: no compiler, executable code, or downloaded fixture."""
    strings = b"\0libc.so.6\0memcpy\0" + version.encode() + b"\0"
    runpath_offset = len(strings)
    if runpath is not None:
        strings += runpath.encode() + b"\0"
    sections = [
        (".dynstr", 3, strings, 0, 0, 0),
        (".dynsym", 11, bytes(24) + struct.pack("<IBBHQQ", 11, 0x22 if weak else 0x12, 0, 0, 0, 0), 1, 1, 24),
        (".gnu.version", 0x6fffffff, struct.pack("<HH", 0, 2), 2, 0, 2),
        (".gnu.version_r", 0x6ffffffe, struct.pack("<HHIII", 1, 1, 1, 16, 0) + struct.pack("<IHHII", 0, 0, 2, 18, 0), 1, 1, 0),
        (".hash", 5, struct.pack("<IIIII", 1, 2, 1, 0, 0), 2, 0, 4),
        (".rela.dyn", 4, struct.pack("<QQq", 0, (1 << 32) | 1, 0), 2, 0, 24),
        (".dynamic", 6, struct.pack("<QQQQ", 1, 1, 0, 0), 1, 0, 16),
    ]
    names = b"\0" + b"".join(s[0].encode() + b"\0" for s in sections) + b".shstrtab\0"
    sections.append((".shstrtab", 3, names, 0, 0, 0))
    body = bytearray(176)
    headers = [bytes(64)]
    dynamic = None
    addresses = {}
    for name, kind, data, link, info, entsize in sections:
        offset = len(body)
        if name == ".dynamic":
            tags = [(1, 1), (4, addresses[".hash"]), (5, addresses[".dynstr"]), (10, len(strings)), (6, addresses[".dynsym"]), (11, 24), (7, addresses[".rela.dyn"]), (8, 24), (9, 24), (0x6ffffff0, addresses[".gnu.version"]), (0x6ffffffe, addresses[".gnu.version_r"]), (0x6fffffff, 1)]
            if runpath is not None:
                tags.append((29, runpath_offset))  # DT_RUNPATH
            data = b"".join(struct.pack("<QQ", tag, value) for tag, value in tags + [(0, 0)])
        addresses[name] = offset
        body.extend(data)
        headers.append(struct.pack("<IIQQQQIIQQ", names.index(name.encode()), kind, 0, offset, offset, len(data), link, info, 1, entsize))
        if name == ".dynamic":
            dynamic = (offset, len(data))
    shoff = len(body)
    body.extend(b"".join(headers))
    body[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9), 3, machine, 1, 0, 64, shoff, 0, 64, 56, 2, 64, len(headers), len(headers) - 1)
    body[64:120] = struct.pack("<IIQQQQQQ", 2, 4, dynamic[0], dynamic[0], 0, dynamic[1], dynamic[1], 8)
    body[120:176] = struct.pack("<IIQQQQQQ", 1, 4, 0, 0, 0, len(body), len(body), 1)
    return body


class ElfInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "fixture.so"

    def test_real_elf_version_and_weak_binding_are_parsed(self):
        for weak in [False, True]:
            self.path.write_bytes(fixture_elf(weak=weak))
            info = read_elf(self.path)
            self.assertEqual(info["needed"], ["libc.so.6"])
            self.assertEqual(info["imports"], [dict(name="memcpy", version="GLIBC_2.35", provider="libc.so.6", weak=weak)])
            self.assertEqual(info["versions"], [dict(name="GLIBC_2.35", provider="libc.so.6", weak=False)])

    def test_corrupt_and_unsupported_elf_are_failures(self):
        for data in [b"\x7fELFbroken", fixture_elf(machine=183), fixture_elf()[:120]]:
            self.path.write_bytes(data)
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                read_elf(self.path)

    def test_defined_copy_relocation_retains_its_provider_requirement(self):
        data = fixture_elf()
        # Second dynsym entry, st_shndx: a copy relocation is defined in the
        # executable but still refers to a version supplied by libc.
        struct.pack_into("<H", data, 176 + len(b"\0libc.so.6\0memcpy\0GLIBC_2.35\0") + 24 + 6, 1)
        self.path.write_bytes(data)
        self.assertEqual(read_elf(self.path)["imports"][0]["provider"], "libc.so.6")

    def test_missing_version_sections_cannot_erase_loader_requirements(self):
        for names in [[b".gnu.version_r"], [b".gnu.version"], [b".gnu.version_r", b".gnu.version"]]:
            data = fixture_elf()
            for name in names:
                data = data.replace(name + b"\0", b"x" * len(name) + b"\0")
            self.path.write_bytes(data)
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "version"):
                read_elf(self.path)

    def test_sections_cannot_redirect_inspection_away_from_loader_bytes(self):
        for section in [3, 7]:  # .gnu.version and .dynamic
            data = fixture_elf()
            table = struct.unpack_from("<Q", data, 40)[0]
            header = table + section * 64
            offset, size = struct.unpack_from("<QQ", data, header + 24)
            struct.pack_into("<Q", data, header + 24, len(data))
            data.extend(data[offset:offset + size])
            self.path.write_bytes(data)
            with self.subTest(section=section), self.assertRaisesRegex(ValueError, "loader"):
                read_elf(self.path)

    def test_loader_hash_and_relocations_prevent_truncating_import_tables(self):
        for truncate_hash in [False, True]:
            data = fixture_elf()
            table = struct.unpack_from("<Q", data, 40)[0]
            struct.pack_into("<Q", data, table + 2 * 64 + 32, 24)
            struct.pack_into("<Q", data, table + 3 * 64 + 32, 2)
            if truncate_hash:
                hash_offset = struct.unpack_from("<Q", data, table + 5 * 64 + 24)[0]
                struct.pack_into("<I", data, hash_offset + 4, 1)
            self.path.write_bytes(data)
            with self.subTest(truncate_hash=truncate_hash), self.assertRaisesRegex(ValueError, "symbol|relocation"):
                read_elf(self.path)

    def test_version_names_must_use_the_loaders_string_table(self):
        data = fixture_elf(version="GLIBC_2.38")
        table = struct.unpack_from("<Q", data, 40)[0]
        count = struct.unpack_from("<H", data, 60)[0]
        decoy = b"\0libc.so.6\0memcpy\0GLIBC_2.35\0"
        data.extend(struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, len(data) + 64, len(decoy), 0, 0, 1, 0))
        data.extend(decoy)
        struct.pack_into("<H", data, 60, count + 1)
        struct.pack_into("<I", data, table + 4 * 64 + 40, count)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "link"):
            read_elf(self.path)

    def test_every_nested_elf_is_discovered_even_without_a_library_suffix(self):
        nested = self.root / "usr/lib/webkit/helpers/worker"
        nested.parent.mkdir(parents=True)
        nested.write_bytes(fixture_elf())
        self.path.write_text("a script")
        self.assertEqual(list(elf_files(self.root)), [nested.resolve()])

    def test_escaping_or_broken_symlinks_are_incomplete_inspections(self):
        self.path.symlink_to("/absent/outside-library")
        with self.assertRaisesRegex(ValueError, "symlink"):
            list(elf_files(self.root))

    def test_squashfs_boundary_is_read_without_executing_runtime(self):
        data = fixture_elf()
        data[8:11] = b"AI\x02"
        self.path.write_bytes(data + b"hsqs")
        self.assertEqual(squashfs_offset(self.path), len(data))
        self.path.write_bytes(data + b"bad!")
        with self.assertRaisesRegex(ValueError, "SquashFS"):
            squashfs_offset(self.path)

    def test_archive_original_ownership_modes_and_launcher_hash(self):
        listing = "\n".join(f"-rwxr-xr-x 0/0 123 2026-10-04 00:00 squashfs-root/{name}" for name in ["AppRun", "AppRun.wrapped", "usr/bin/cmtrace-open"])
        (self.root / "AppRun.wrapped").write_bytes(b"owned fixture")
        digest = hashlib.sha256(b"owned fixture").hexdigest()
        validate_launchers(listing, self.root, digest)
        for bad in [listing.replace("-rwxr-xr-x", "-rwxrwx---", 1), listing.replace("0/0", "1000/1000", 1), listing.replace("AppRun.wrapped", "missing"), listing + "\n" + listing]:
            with self.subTest(listing=bad), self.assertRaisesRegex(ValueError, "launcher"):
                validate_launchers(bad, self.root, digest)
        with self.assertRaisesRegex(ValueError, "checksum"):
            validate_launchers(listing, self.root, "0" * 64)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.info = dict(path="plugin.so", needed=["libc.so.6"], versions=[], imports=[])
        self.tree = dict(needed=["libc.so.6"], libs={"libc.so.6": dict(realpath="/lib/libc.so.6", needed=[])})

    def test_complete_dependency_resolution(self):
        self.assertEqual(validate_closure(self.info, self.tree, lambda _: dict(needed=[])), {"libc.so.6": dict(needed=[])})

    def test_missing_transitive_dependency_is_a_failure(self):
        self.tree["libs"]["libc.so.6"]["needed"] = ["absent.so"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_closure(self.info, self.tree, lambda _: dict(needed=["absent.so"]))

    def test_unresolved_or_parser_omissions_cannot_pass(self):
        for tree in [dict(needed=[], libs={}), dict(needed=["libc.so.6"], libs={}), dict(needed=["libc.so.6"], libs={"libc.so.6": dict(realpath=None, needed=[])})]:
            with self.subTest(tree=tree), self.assertRaisesRegex(ValueError, "incomplete|unresolved"):
                validate_closure(self.info, tree, lambda _: dict(needed=[]))

    def test_provider_parse_failure_propagates(self):
        def broken(_):
            raise ValueError("bad ELF provider")
        with self.assertRaisesRegex(ValueError, "bad ELF"):
            validate_closure(self.info, self.tree, broken)

    def test_resolver_warning_cannot_skip_a_bad_library_and_pass_with_a_host_fallback(self):
        def fallback(*args, **kwargs):
            print("lddtree: warning: AppDir/usr/lib/libc.so.6: Magic number does not match", file=sys.stderr)
            return self.tree
        with patch("auditwheel.lddtree.ldd", side_effect=fallback), self.assertRaisesRegex(ValueError, "resolver warning"):
            resolve_tree("plugin.so", {})

    def test_pinned_resolver_reads_owned_elf_bytes_without_executing_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "plugin.so"
            main.write_bytes(fixture_elf())
            library_dir = root / "libraries"
            library_dir.mkdir()
            provider = library_dir / "libc.so.6"
            data = fixture_elf()
            dynamic_offset = struct.unpack_from("<Q", data, 64 + 8)[0]
            struct.pack_into("<Q", data, dynamic_offset, 21)  # DT_DEBUG, no DT_NEEDED
            provider.write_bytes(data)
            paths = dict(conf=[], env=[str(library_dir)], interp=[])
            tree = resolve_tree(main, paths)
            self.assertEqual(tree["needed"], ("libc.so.6",))
            self.assertEqual(tree["libs"]["libc.so.6"]["realpath"], provider)
            validate_closure(read_elf(main), tree, read_elf)
            bad_dir = root / "earlier"
            bad_dir.mkdir()
            (bad_dir / "libc.so.6").write_bytes(b"corrupt former ELF")
            paths["env"].insert(0, str(bad_dir))
            with self.assertRaisesRegex(Exception, "Magic number"):
                resolve_tree(main, paths)

    def test_runpath_cannot_hide_a_conflicting_launcher_environment_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "helpers/worker"
            private = worker.parent / "private"
            environment = root / "usr/lib"
            private.mkdir(parents=True)
            environment.mkdir(parents=True)
            worker.write_bytes(fixture_elf(runpath="$ORIGIN/private"))
            provider = private / "libc.so.6"
            data = fixture_elf()
            dynamic_offset = struct.unpack_from("<Q", data, 72)[0]
            struct.pack_into("<Q", data, dynamic_offset, 21)  # no dependencies
            provider.write_bytes(data)
            paths = dict(conf=[], env=[str(environment)], interp=[])
            self.assertEqual(resolve_tree(worker, paths)["libs"]["libc.so.6"]["realpath"], provider)
            competing = environment / "libc.so.6"
            competing.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "conflicting.*LD_LIBRARY_PATH"):
                resolve_tree(worker, paths)
            competing.unlink()
            competing.symlink_to(provider)
            self.assertEqual(resolve_tree(worker, paths)["libs"]["libc.so.6"]["realpath"], provider)


class BuildContextTests(unittest.TestCase):
    def test_missing_stale_duplicate_and_symlink_artifacts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            select_artifact(root, "1.6.0", before_build=True)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                select_artifact(root, "1.6.0")
            appimage = root / "appimage/CMTrace Open_1.6.0_amd64.AppImage"
            appimage.parent.mkdir()
            appimage.write_bytes(b"fixture")
            self.assertEqual(select_artifact(root, "1.6.0"), appimage)
            with self.assertRaisesRegex(ValueError, "stale"):
                select_artifact(root, "1.6.0", before_build=True)
            with self.assertRaisesRegex(ValueError, "current-version"):
                select_artifact(root, "1.7.0")
            extra = root / "extra.AppImage"
            extra.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                select_artifact(root, "1.6.0")
            extra.unlink()
            appimage.unlink()
            appimage.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "symlink"):
                select_artifact(root, "1.6.0")

    def test_only_installed_official_trusted_jammy_origins_are_accepted(self):
        def version(origin="Ubuntu", archive="jammy-updates", trusted=True):
            return SimpleNamespace(origins=[SimpleNamespace(origin=origin, archive=archive, trusted=trusted, site="archive.ubuntu.com")])
        self.assertEqual(jammy_origins(version()), [dict(origin="Ubuntu", archive="jammy-updates", site="archive.ubuntu.com")])
        for bad in [version(archive="noble"), version(origin="LP-PPA-test"), version(trusted=False), SimpleNamespace(origins=[])]:
            with self.assertRaisesRegex(ValueError, "Jammy"):
                jammy_origins(bad)

    def test_superseded_provider_error_identifies_package_version_and_empty_origins(self):
        installed = SimpleNamespace(version="2.11.1+dfsg-1ubuntu0.3", origins=[])
        cache = {"libfreetype6:amd64": SimpleNamespace(installed=installed)}
        with self.assertRaises(ValueError) as failure:
            package_record(cache, "libfreetype6:amd64")
        message = str(failure.exception)
        for detail in ["libfreetype6:amd64", installed.version, "trusted official Jammy", "observed origins=[]"]:
            self.assertIn(detail, message)

    def test_rejected_provider_error_reports_origins_without_accepting_them(self):
        for origin, archive, trusted in [("Ubuntu", "jammy-security", False), ("Ubuntu", "noble", True), ("LP-PPA-test", "jammy", True)]:
            observed = dict(origin=origin, archive=archive, site="packages.example", trusted=trusted)
            installed = SimpleNamespace(version="1.0", origins=[SimpleNamespace(**observed)])
            cache = {"provider:amd64": SimpleNamespace(installed=installed)}
            with self.subTest(origin=origin, archive=archive, trusted=trusted), self.assertRaises(ValueError) as failure:
                package_record(cache, "provider:amd64")
            self.assertIn("provider:amd64", str(failure.exception))
            self.assertIn(repr([observed]), str(failure.exception))

    def test_provider_record_retains_only_trusted_official_jammy_origins(self):
        official = dict(origin="Ubuntu", archive="jammy-security", site="archive.ubuntu.com")
        installed = SimpleNamespace(version="2.11.1+dfsg-1ubuntu0.4", origins=[
            SimpleNamespace(**official, trusted=True),
            SimpleNamespace(origin="LP-PPA-test", archive="jammy", site="packages.example", trusted=True),
        ])
        cache = {"libfreetype6:amd64": SimpleNamespace(installed=installed)}
        self.assertEqual(package_record(cache, "libfreetype6:amd64"), dict(version=installed.version, origins=[official]))

    def test_missing_provider_still_fails_with_its_package_name(self):
        with self.assertRaisesRegex(ValueError, "required package is not installed: missing:amd64"):
            package_record({"missing:amd64": SimpleNamespace(installed=None)}, "missing:amd64")


class ImportPolicyTests(unittest.TestCase):
    def setUp(self):
        self.info = {
            "path": "AppDir/usr/lib/nested/plugin.so",
            "imports": [dict(name="memcpy", version="GLIBC_2.14", provider="libc.so.6", weak=False)],
            "versions": [dict(name="GLIBC_2.14", provider="libc.so.6", weak=False)],
        }
        self.providers = {"libc.so.6": {"definitions": ["GLIBC_2.14"], "exports": [["memcpy", "GLIBC_2.14"]]}}

    def test_safe_floor_and_exact_provider_symbol(self):
        validate_imports(self.info, self.providers)

    def test_strong_glibc_238_is_rejected_even_when_a_provider_has_it(self):
        info = copy.deepcopy(self.info)
        info["imports"][0]["version"] = "GLIBC_2.38"
        with self.assertRaisesRegex(ValueError, "GLIBC_2.38.*2.35"):
            validate_imports(info, self.providers)

    def test_weak_import_is_recorded_without_a_strong_floor_claim(self):
        self.info["imports"][0].update(version="GLIBC_2.38", weak=True)
        validate_imports(self.info, self.providers)

    def test_weak_symbol_does_not_excuse_a_strong_version_requirement(self):
        self.info["imports"][0].update(version="GLIBC_2.38", weak=True)
        self.info["versions"][0]["name"] = "GLIBC_2.38"
        with self.assertRaisesRegex(ValueError, "version.*GLIBC_2.38"):
            validate_imports(self.info, self.providers)

    def test_missing_provider_version_and_symbol_are_failures(self):
        for providers, message in [({}, "provider"), ({"libc.so.6": {"definitions": [], "exports": []}}, "version"), ({"libc.so.6": {"definitions": ["GLIBC_2.14"], "exports": []}}, "symbol")]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                validate_imports(self.info, providers)

    def test_glibcxx_and_cxxabi_require_the_actual_provider(self):
        for version in ["GLIBCXX_3.4.30", "CXXABI_1.3.13"]:
            self.info["versions"] = [dict(name=version, provider="libstdc++.so.6", weak=False)]
            with self.assertRaisesRegex(ValueError, "provider"):
                validate_imports(self.info, self.providers)


if __name__ == "__main__":
    unittest.main()

"""Read-only AppImage inspection. Never execute the runtime or use ldd."""

import re
import os
import hashlib
import contextlib
import io
import json
import logging
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LAUNCHER_SHA256 = "f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f"
BUNDLE_ROOT = "src-tauri/target/x86_64-unknown-linux-gnu/release/bundle"
# The search order is encoded in the checksum-pinned AppRun.wrapped. It is
# supplied to auditwheel's static resolver for RPATH/RUNPATH and DT_NEEDED.
LAUNCHER_LIBRARY_DIRS = ["usr/lib", "usr/lib/i386-linux-gnu", "usr/lib/x86_64-linux-gnu", "usr/lib32", "usr/lib64", "lib", "lib/i386-linux-gnu", "lib/x86_64-linux-gnu", "lib32", "lib64"]


def select_artifact(root, version, before_build=False):
    artifacts = []
    for path in root.rglob("*"):
        if path.suffix.lower() == ".appimage":
            if path.is_symlink():
                raise ValueError(f"AppImage is a symlink: {path}")
            artifacts.append(path)
    if before_build:
        if artifacts:
            raise ValueError("stale AppImage exists before build; clean bundle outputs")
        return None
    if len(artifacts) != 1:
        raise ValueError("expected exactly one final AppImage")
    artifact = artifacts[0]
    if artifact.parent != root / "appimage" or artifact.name != f"CMTrace Open_{version}_amd64.AppImage" or not artifact.is_file():
        raise ValueError("expected current-version x86_64 AppImage in appimage/")
    return artifact


def jammy_origins(version):
    origins = [dict(origin=item.origin, archive=item.archive, site=item.site) for item in version.origins if item.trusted and item.origin == "Ubuntu" and item.archive in ("jammy", "jammy-updates", "jammy-security")]
    if not origins:
        raise ValueError("provider is not available from a trusted official Jammy archive")
    return origins


def validate_launchers(listing, root, expected_hash):
    for name in ("AppRun", "AppRun.wrapped", "usr/bin/cmtrace-open"):
        rows = [line.split() for line in listing.splitlines() if line.endswith(" squashfs-root/" + name)]
        if len(rows) != 1 or rows[0][:2] != ["-rwxr-xr-x", "0/0"]:
            raise ValueError(f"archive launcher must be root-owned 0755: {name}")
    if sha256(Path(root) / "AppRun.wrapped") != expected_hash:
        raise ValueError("AppRun.wrapped checksum differs from pinned launcher")


def squashfs_offset(path):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as stream:
        if stream.read(11)[8:] != b"AI\x02":
            raise ValueError("expected type-2 AppImage")
        stream.seek(0)
        elf = ELFFile(stream)
        offset = elf["e_shoff"] + elf["e_shentsize"] * elf.num_sections()
        if not elf["e_shoff"] or not elf.num_sections():
            raise ValueError("missing AppImage section boundary")
        stream.seek(offset)
        if stream.read(4) != b"hsqs":
            raise ValueError("SquashFS missing at ELF boundary")
        return offset


def validate_closure(info, tree, read):
    if set(tree["needed"]) != set(info["needed"]) or not set(info["needed"]) <= tree["libs"].keys():
        raise ValueError(f"incomplete dependency scan: {info['path']}")
    providers = {}
    for name, resolved in tree["libs"].items():
        if not resolved["realpath"]:
            raise ValueError(f"unresolved provider {name} for {info['path']}")
        provider = read(resolved["realpath"])
        if set(provider["needed"]) != set(resolved["needed"]) or not set(provider["needed"]) <= tree["libs"].keys():
            raise ValueError(f"incomplete transitive scan of {name}")
        providers[name] = provider
    return providers


def resolve_tree(path, ldpaths):
    # This is auditwheel's Python ELF reader, not the native `ldd` command.
    from auditwheel.lddtree import find_lib, ldd
    diagnostics = io.StringIO()
    logger = logging.getLogger("auditwheel")
    handler = logging.StreamHandler(diagnostics)
    handler.setLevel(logging.WARNING)
    previous_level = logger.level
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    try:
        with contextlib.redirect_stderr(diagnostics), contextlib.redirect_stdout(diagnostics):
            tree = ldd(Path(path), ldpaths=ldpaths)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    if diagnostics.getvalue():
        raise ValueError(f"incomplete dependency scan (resolver warning) for {path}: {diagnostics.getvalue().strip()}")
    # auditwheel searches RUNPATH before LD_LIBRARY_PATH, unlike glibc.
    # Reject conflicting selections instead of certifying a provider
    # the launcher may not load. This also conservatively rejects
    # RPATH conflicts; same-realpath symlink aliases remain valid.
    for name, library in tree.libraries.items():
        candidate, _ = find_lib(tree.platform, name, ldpaths.get("env", []))
        if candidate is not None and (library.realpath is None or candidate.resolve() != library.realpath.resolve()):
            raise ValueError(f"conflicting provider in LD_LIBRARY_PATH for {name}: {candidate} versus {library.realpath}")
    return dict(needed=tree.needed, libs={name: dict(realpath=library.realpath, needed=library.needed) for name, library in tree.libraries.items()})


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_elf(path):
    from elftools.elf.elffile import ELFFile

    try:
        with open(path, "rb") as stream:
            elf = ELFFile(stream)
            if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64" or elf["e_type"] not in ("ET_EXEC", "ET_DYN"):
                raise ValueError("unsupported ELF architecture/type")
            # Sectionless/partly stripped metadata is incomplete, never a pass.
            sections = list(elf.iter_sections())
            if not sections:
                raise ValueError("missing ELF section table")
            size = os.fstat(stream.fileno()).st_size
            for section in sections:
                if section["sh_type"] != "SHT_NOBITS" and section["sh_offset"] + section["sh_size"] > size:
                    raise ValueError("truncated ELF section")
            info = dict(path=str(path), needed=[], rpath=[], runpath=[], versions=[], imports=[], definitions=[], exports=[])
            dynamic = elf.get_section_by_name(".dynamic")
            dynamic_segments = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_DYNAMIC"]
            tags = {}
            if dynamic:
                if len(dynamic_segments) != 1 or dynamic_segments[0]["p_offset"] != dynamic["sh_offset"] or dynamic_segments[0]["p_filesz"] != dynamic["sh_size"]:
                    raise ValueError("dynamic section differs from loader PT_DYNAMIC")
                for tag in dynamic.iter_tags():
                    tags[tag.entry.d_tag] = tag.entry.d_val
                    if tag.entry.d_tag == "DT_NEEDED":
                        info["needed"].append(tag.needed)
                    elif tag.entry.d_tag == "DT_RPATH":
                        info["rpath"].append(tag.rpath)
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        info["runpath"].append(tag.runpath)
            elif any(segment["p_type"] == "PT_DYNAMIC" for segment in elf.iter_segments()):
                raise ValueError("missing dynamic section")
            # Section names alone are not authoritative. The loader follows
            # dynamic addresses/counts; renamed/truncated version metadata must
            # not turn required imports into an empty successful scan.
            for tag, section_name, count_tag in [
                ("DT_SYMTAB", ".dynsym", None),
                ("DT_STRTAB", ".dynstr", None),
                ("DT_VERSYM", ".gnu.version", None),
                ("DT_VERNEED", ".gnu.version_r", "DT_VERNEEDNUM"),
                ("DT_VERDEF", ".gnu.version_d", "DT_VERDEFNUM"),
                ("DT_HASH", ".hash", None),
                ("DT_GNU_HASH", ".gnu.hash", None),
            ]:
                section = elf.get_section_by_name(section_name)
                if tag in tags and (section is None or section["sh_addr"] != tags[tag]):
                    raise ValueError(f"missing/mismatched ELF metadata: {section_name}")
                if tag in tags and list(elf.address_offsets(tags[tag], section["sh_size"])) != [section["sh_offset"]]:
                    raise ValueError(f"section differs from loader mapping: {section_name}")
                if section is not None and tag not in tags:
                    raise ValueError(f"unsupported ELF metadata without {tag}: {section_name}")
                if count_tag and ((count_tag in tags) != (tag in tags) or (section is not None and section["sh_info"] != tags.get(count_tag))):
                    raise ValueError(f"incomplete ELF version count: {section_name}")
            # pyelftools follows section links for names and version indices.
            # Bind every such link to the same tables the loader addresses.
            for name, linked_name in [
                (".dynamic", ".dynstr"), (".dynsym", ".dynstr"),
                (".gnu.version_r", ".dynstr"), (".gnu.version_d", ".dynstr"),
                (".gnu.version", ".dynsym"), (".hash", ".dynsym"),
                (".gnu.hash", ".dynsym"),
            ]:
                section = elf.get_section_by_name(name)
                if section is not None and section["sh_link"] != elf.get_section_index(linked_name):
                    raise ValueError(f"section link differs from loader metadata: {name}")
            required = {}
            verneed = elf.get_section_by_name(".gnu.version_r")
            if verneed:
                for version, auxiliaries in verneed.iter_versions():
                    for aux in auxiliaries:
                        item = dict(name=aux.name, provider=version.name, weak=bool(aux["vna_flags"] & 2))
                        required[aux["vna_other"] & 0x7fff] = item
                        info["versions"].append(item)
            defined = {}
            verdef = elf.get_section_by_name(".gnu.version_d")
            if verdef:
                for version, auxiliaries in verdef.iter_versions():
                    name = next(auxiliaries).name
                    defined[version["vd_ndx"] & 0x7fff] = name
                    info["definitions"].append(name)
            dynsym = elf.get_section_by_name(".dynsym")
            versym = elf.get_section_by_name(".gnu.version")
            if dynamic and dynsym is None:
                raise ValueError("missing dynamic symbols")
            if (verneed or verdef) and versym is None:
                raise ValueError("missing symbol version indices")
            if dynsym:
                hashes = [elf.get_section_by_name(name) for name in (".hash", ".gnu.hash") if elf.get_section_by_name(name) is not None]
                if not hashes or any(table.get_number_of_symbols() != dynsym.num_symbols() for table in hashes):
                    raise ValueError("incomplete dynamic symbols: loader hash count differs")
                if versym and versym.num_symbols() != dynsym.num_symbols():
                    raise ValueError("incomplete symbol version indices")
                for address_tag, size_tag in [("DT_RELA", "DT_RELASZ"), ("DT_REL", "DT_RELSZ"), ("DT_JMPREL", "DT_PLTRELSZ")]:
                    if address_tag not in tags:
                        if tags.get(size_tag, 0):
                            raise ValueError("missing loader relocation address")
                        continue
                    matches = [section for section in sections if section["sh_type"] in ("SHT_RELA", "SHT_REL") and section["sh_addr"] == tags[address_tag] and section["sh_size"] == tags.get(size_tag)]
                    if len(matches) != 1 or list(elf.address_offsets(tags[address_tag], matches[0]["sh_size"])) != [matches[0]["sh_offset"]]:
                        raise ValueError("incomplete loader relocation metadata")
                    relocation_table = matches[0]
                    if relocation_table["sh_link"] != elf.get_section_index(".dynsym"):
                        raise ValueError("relocations reference a different symbol table")
                    if any(relocation["r_info_sym"] >= dynsym.num_symbols() for relocation in relocation_table.iter_relocations()):
                        raise ValueError("loader relocation references missing dynamic symbol")
                for index, symbol in enumerate(dynsym.iter_symbols()):
                    vindex = versym.get_symbol(index)["ndx"] if versym else 0
                    vindex = (vindex & 0x7fff) if isinstance(vindex, int) else 0
                    if symbol["st_shndx"] == "SHN_UNDEF" or vindex in required:
                        if vindex > 1:
                            requirement = required.get(vindex)
                            if requirement is None:
                                raise ValueError("unknown import version index")
                            info["imports"].append(dict(name=symbol.name, version=requirement["name"], provider=requirement["provider"], weak=symbol["st_info"]["bind"] == "STB_WEAK"))
                    elif symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE"):
                        if vindex > 1 and vindex not in defined:
                            raise ValueError("unknown export version index")
                        info["exports"].append([symbol.name, defined.get(vindex, "")])
            return info
    except Exception as error:
        raise ValueError(f"ELF inspection failed for {path}: {error}") from error


def elf_files(root):
    root = Path(root).resolve(strict=True)
    def failed(error):
        raise error
    for directory, dirs, files in os.walk(root, onerror=failed, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            if path.is_symlink():
                target = path.resolve()
                if not target.is_relative_to(root) or not target.exists():
                    raise ValueError(f"escaping or broken AppDir symlink: {path}")
                continue
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError(f"unsupported archive entry: {path}")
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    yield path


def check_glibc_floor(version):
    match = re.fullmatch(r"GLIBC_(\d+(?:\.\d+)+)", version)
    if match and tuple(map(int, match[1].split("."))) > (2, 35):
        raise ValueError(f"strong import {version} exceeds GLIBC_2.35")
    if version.startswith("GLIBC_") and not match:
        raise ValueError(f"unsupported GLIBC requirement {version}")


def validate_imports(info, providers, shipped=True):
    # Version-need flags and weak symbol bindings are separate ELF contracts.
    # A weak symbol does not excuse a non-weak loader version requirement.
    for requirement in info["versions"]:
        if requirement["weak"]:
            continue
        provider = providers.get(requirement["provider"])
        if provider is None:
            raise ValueError(f"unresolved provider {requirement['provider']}")
        if requirement["name"] not in provider["definitions"]:
            raise ValueError(f"missing version {requirement['name']} in {requirement['provider']}")
    imported_providers = {symbol["provider"] for symbol in info["imports"] if not symbol["weak"]}
    export_sets = {name: set(map(tuple, providers[name]["exports"])) for name in imported_providers if name in providers}
    for symbol in info["imports"]:
        if symbol["weak"]:
            continue
        if shipped:
            check_glibc_floor(symbol["version"])
        provider = providers.get(symbol["provider"])
        if provider is None:
            raise ValueError(f"unresolved provider {symbol['provider']}")
        if (symbol["name"], symbol["version"]) not in export_sets[symbol["provider"]]:
            raise ValueError(f"missing symbol {symbol['name']}@{symbol['version']} in {symbol['provider']}")


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=180, env={**os.environ, "LC_ALL": "C"}).stdout.strip()


def package_record(cache, name):
    installed = cache[name].installed
    if installed is None:
        raise ValueError(f"required package is not installed: {name}")
    return dict(version=installed.version, origins=jammy_origins(installed))


def build_context():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("ABI provider inspection requires the Ubuntu 22.04 x86_64 build host")
    os_release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if os_release.get("ID", "").strip('"') != "ubuntu" or os_release.get("VERSION_ID", "").strip('"') != "22.04":
        raise ValueError("AppImage producer must run on Ubuntu 22.04")
    import apt
    import elftools
    from importlib.metadata import version as package_version
    cache = apt.Cache()
    packages = {name: package_record(cache, name) for name in ["libc6", "libstdc++6", "libwebkit2gtk-4.1-0", "libjavascriptcoregtk-4.1-0", "libgtk-3-0", "squashfs-tools", "python3-apt"]}
    for tool in ["unsquashfs"]:
        if not shutil.which(tool):
            raise ValueError(f"missing archive inspection tool: {tool}")
    context = dict(
        os=os_release, packages=packages, pyelftools=elftools.__version__,
        inspection_tools={name: package_version(name) for name in ["auditwheel", "pyelftools", "packaging"]},
        built_commit=command("git", "rev-parse", "HEAD"),
        built_tree=command("git", "rev-parse", "HEAD^{tree}"),
        source_commit=os.environ.get("SOURCE_COMMIT") or command("git", "rev-parse", "HEAD"),
        workflow_commit=os.environ.get("GITHUB_SHA"),
        image={name: os.environ.get(name) for name in ["ImageOS", "ImageVersion", "RUNNER_ARCH", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]},
        toolchain={name: command(name, "--version") for name in ["node", "cargo", "rustc"]},
        inputs={name: sha256(name) for name in ["Cargo.lock", "package-lock.json", "src-tauri/tauri.conf.json", "src-tauri/tauri.appimage.conf.json", "scripts/appimage-abi-requirements.txt"]},
        version=json.loads(Path("package.json").read_text())["version"],
    )
    if not re.fullmatch(r"[0-9a-f]{40}", context["source_commit"] or ""):
        raise ValueError("SOURCE_COMMIT must identify the exact workflow source")
    return context, cache


def tool_hashes():
    # These are the resolved cached inputs, after Tauri's linuxdeploy marker
    # patch. Recording mutable master/continuous bytes is not reproducibility.
    config = json.loads(Path("src-tauri/tauri.conf.json").read_text())
    if config.get("bundle", {}).get("useLocalToolsDir"):
        raise ValueError("workflow tool provenance requires the configured global Tauri cache")
    xdg = Path(os.environ.get("XDG_CACHE_HOME", ""))
    cache = (xdg if xdg.is_absolute() else Path.home() / ".cache") / "tauri"
    names = ["AppRun-x86_64", "linuxdeploy-x86_64.AppImage", "linuxdeploy-plugin-gtk.sh", "linuxdeploy-plugin-gstreamer.sh", "linuxdeploy-plugin-appimage.AppImage"]
    result = {}
    for name in names:
        path = cache / name
        if not path.is_file():
            if name == "linuxdeploy-plugin-appimage.AppImage":
                result[name] = dict(present=False, note="Tauri may use linuxdeploy's built-in plugin")
                continue
            raise ValueError(f"missing bundler input provenance: {name}")
        result[name] = dict(present=True, sha256=sha256(path), bytes=path.stat().st_size)
    return dict(stage="cached bytes after bundling", mutable_inputs=True, files=result)


def inspect_artifact(artifact, cache):
    digest = sha256(artifact)
    # Only hash-pinned inspection libraries are loaded; never import AppDir code.
    from auditwheel.lddtree import load_ld_paths
    from auditwheel.libc import Libc
    host_paths = load_ld_paths(Libc.GLIBC)
    host_paths["env"] = []
    result = dict(artifact=artifact.name, sha256=digest, bytes=artifact.stat().st_size, elf=[], system_providers={})
    with tempfile.TemporaryDirectory(prefix="cmtrace-appimage-abi-") as temporary:
        appdir = Path(temporary) / "AppDir"
        offset = str(squashfs_offset(artifact))
        listing = command("unsquashfs", "-lln", "-o", offset, str(artifact))
        command("unsquashfs", "-no-progress", "-no-xattrs", "-processors", "2", "-o", offset, "-d", str(appdir), str(artifact))
        validate_launchers(listing, appdir, LAUNCHER_SHA256)
        files = [artifact, *elf_files(appdir)]
        if appdir / "usr/bin/cmtrace-open" not in files or appdir / "AppRun.wrapped" not in files:
            raise ValueError("required application/launcher ELF was not inspected")
        parsed = {}
        selected = {}

        def read(path):
            path = Path(path).resolve(strict=True)
            if path not in parsed:
                parsed[path] = read_elf(path)
                if path != artifact and not path.is_relative_to(appdir):
                    aliases = [path]
                    if str(path).startswith("/usr/lib/"):
                        aliases.append(Path(str(path).removeprefix("/usr")))
                    owners = set()
                    for alias in aliases:
                        query = subprocess.run(["dpkg-query", "-S", str(alias)], capture_output=True, text=True, timeout=30)
                        if query.returncode == 0:
                            owners.update(line.split(": ", 1)[0] for line in query.stdout.splitlines())
                    if len(owners) != 1:
                        raise ValueError(f"unowned/ambiguous system provider: {path}")
                    owner = owners.pop()
                    result["system_providers"][str(path)] = dict(package=owner, sha256=sha256(path), **package_record(cache, owner))
            return parsed[path]

        for path in files:
            info = read(path)
            ldpaths = dict(host_paths)
            # Runtime and wrapped launcher load before AppRun sets LD_LIBRARY_PATH.
            ldpaths["env"] = [] if path in (artifact, appdir / "AppRun.wrapped") else [str(appdir / name) for name in LAUNCHER_LIBRARY_DIRS]
            tree = resolve_tree(path, ldpaths)
            providers = validate_closure(info, tree, read)
            for name, provider in providers.items():
                provider_path = Path(provider["path"])
                identity = sha256(provider_path)
                if name in selected and selected[name] != identity:
                    raise ValueError(f"ambiguous provider across ELF contexts: {name}")
                selected[name] = identity
                validate_imports(provider, providers, shipped=provider_path.is_relative_to(appdir))
            validate_imports(info, providers)
            record = {name: value for name, value in info.items() if name != "exports"}
            record["path"] = str(path.relative_to(appdir)) if path.is_relative_to(appdir) else "<AppImage runtime>"
            record["providers"] = {name: str(Path(value["path"]).relative_to(appdir)) if Path(value["path"]).is_relative_to(appdir) else value["path"] for name, value in providers.items()}
            result["elf"].append(record)
    if sha256(artifact) != digest:
        raise ValueError("AppImage changed during read-only inspection")
    result["verdict"] = "archive modes, strong GLIBC <= 2.35 and static versioned dependency closure passed; runtime untested"
    return result


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("preflight", "verify") or sys.argv[2] != BUNDLE_ROOT:
        raise ValueError(f"usage: appimage_abi.py preflight|verify {BUNDLE_ROOT}")
    root = Path.cwd()
    for part in BUNDLE_ROOT.split("/") + ["appimage"]:
        root = root / part
        if root.is_symlink():
            raise ValueError(f"verification root traverses symlink: {root}")
    root = Path.cwd() / BUNDLE_ROOT
    context, cache = build_context()
    report_dir = root / "provenance"
    pending = report_dir / "appimage-inspection-pending.json"
    if sys.argv[1] == "preflight":
        select_artifact(root, context["version"], before_build=True)
        report_dir.mkdir(parents=True, exist_ok=True)
        pending.write_text(json.dumps(context, indent=2) + "\n")
        print("AppImage preflight: Ubuntu 22.04 packages and empty output verified")
    else:
        if json.loads(pending.read_text()) != context:
            raise ValueError("build context changed since AppImage preflight")
        artifact = select_artifact(root, context["version"])
        report = dict(build=context, bundler_tools=tool_hashes(), inspection=inspect_artifact(artifact, cache))
        (report_dir / "appimage-abi.json").write_text(json.dumps(report, indent=2) + "\n")
        pending.unlink()
        print(f"AppImage ABI inspection passed: {report['inspection']['sha256']}; runtime untested")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"AppImage inspection FAILED: {error}", file=sys.stderr)
        sys.exit(1)

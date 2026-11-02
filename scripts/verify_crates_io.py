#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license.
"""Check that this checkout reproduces published crates.io packages.

For each crate, `cargo package --no-verify --allow-dirty -p <crate>` is run
in this workspace and the resulting .crate is compared, file by file, with
the tarball downloaded from static.crates.io. A crate passes when both have
the same file list and every file is byte-identical, except:

- `.cargo_vcs_info.json`, which names the commit a package was cut from; it
  is reported (the published commit) but not compared, since a fork commit
  necessarily differs;
- `Cargo.lock`, which cargo resolves against the registry at packaging time;
  it is reported when it differs but does not fail the check (library
  consumers never read it).

The downloaded tarball's SHA-256 is checked against `--lock` (a consumer's
Cargo.lock, e.g. kogany's) when given, so the comparison is against exactly
the package the consumer builds.

Usage:
    scripts/verify_crates_io.py --scratch DIR [--lock PATH] [CRATE[@VERSION] ...]

Without crate arguments the zakura-* crates kogany patches from this fork
are checked. The version defaults to the one this workspace declares.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The crates kogany patches from this fork: the whole published closure of
# the 5.0.0-rc.2 release (udon and bento stay on crates.io, see kogany's
# root Cargo.toml).
DEFAULT_CRATES = [
    "zakura-address",
    "zakura-bellman",
    "zakura-bls12-381",
    "zakura-equihash",
    "zakura-halo2-gadgets",
    "zakura-halo2-poseidon",
    "zakura-halo2-proofs",
    "zakura-jubjub",
    "zakura-note-encryption",
    "zakura-orchard",
    "zakura-orchard-legacy",
    "zakura-pairing",
    "zakura-pasta-curves",
    "zakura-primitives",
    "zakura-protocol",
    "zakura-reddsa",
    "zakura-redjubjub",
    "zakura-sapling-crypto",
    "zakura-sensei",
    "zakura-sensei-artifacts",
    "zakura-sensei-macros",
    "zakura-sensei-shared",
    "zakura-sinsemilla",
    "zakura-transparent",
    "zakura-zcash-script",
]

IGNORED = {".cargo_vcs_info.json"}
INFORMATIONAL = {"Cargo.lock"}


def workspace_crates() -> dict[str, tuple[Path, str]]:
    """Map package name -> (crate dir, version) for every workspace member."""
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())
    ws_version = root["workspace"]["package"]["version"]
    out = {}
    for member in root["workspace"]["members"]:
        manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text())
        pkg = manifest["package"]
        version = pkg["version"]
        if isinstance(version, dict):
            version = ws_version
        out[pkg["name"]] = (ROOT / member, version)
    return out


def lock_checksums(lock: Path) -> dict[tuple[str, str], str]:
    data = tomllib.loads(lock.read_text())
    return {
        (p["name"], p["version"]): p["checksum"]
        for p in data.get("package", [])
        if "checksum" in p
    }


def read_crate(blob: bytes) -> dict[str, bytes]:
    """Read a .crate into {relative path: bytes}, without touching the disk."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.split("/", 1)[1] if "/" in member.name else member.name
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError(f"unsafe path in archive: {member.name}")
            f = tar.extractfile(member)
            assert f is not None
            files[name] = f.read()
    return files


def download(name: str, version: str, dest: Path) -> bytes:
    path = dest / f"{name}-{version}.crate"
    if not path.exists():
        url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        with urllib.request.urlopen(url) as resp:  # noqa: S310 (fixed https host)
            path.write_bytes(resp.read())
    return path.read_bytes()


def package(name: str, version: str, target: Path) -> bytes:
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(
        ["cargo", "package", "--no-verify", "--allow-dirty", "-p", name],
        cwd=ROOT,
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return (target / "package" / f"{name}-{version}.crate").read_bytes()


def compare(name: str, version: str, args, members, checksums) -> bool:
    crate_dir, ws_version = members[name]
    version = version or ws_version
    published = download(name, version, args.scratch / "registry")
    digest = hashlib.sha256(published).hexdigest()
    ok = True
    expected = checksums.get((name, version))
    if checksums and expected is None:
        print(f"  {name} {version}: not in {args.lock}")
        ok = False
    elif expected and expected != digest:
        print(f"  {name} {version}: downloaded {digest} != lock {expected}")
        ok = False

    pub = read_crate(published)
    local = read_crate(package(name, version, args.scratch / "target"))
    vcs = json.loads(pub.get(".cargo_vcs_info.json", b"{}") or b"{}")
    sha = vcs.get("git", {}).get("sha1", "?")

    only_pub = sorted(set(pub) - set(local) - IGNORED)
    only_local = sorted(set(local) - set(pub) - IGNORED)
    differ = sorted(
        f for f in set(pub) & set(local) if f not in IGNORED and pub[f] != local[f]
    )
    hard = [f for f in differ if f not in INFORMATIONAL]
    soft = [f for f in differ if f in INFORMATIONAL]
    if only_pub or only_local or hard:
        ok = False
    status = "OK  " if ok else "FAIL"
    print(
        f"{status} {name} {version}  sha256 {digest[:16]}…  "
        f"published from {sha[:12]}  files {len(pub)}"
    )
    for f in only_pub:
        print(f"    only in crates.io: {f}")
    for f in only_local:
        print(f"    only in this tree: {f}")
    for f in hard:
        print(f"    differs: {f}")
    for f in soft:
        print(f"    differs (informational): {f}")
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("crates", nargs="*", help="CRATE or CRATE@VERSION")
    parser.add_argument("--scratch", type=Path, required=True,
                        help="empty scratch directory for downloads and cargo output")
    parser.add_argument("--lock", type=Path, help="consumer Cargo.lock for checksums")
    args = parser.parse_args(argv)
    args.scratch = args.scratch.resolve()
    (args.scratch / "registry").mkdir(parents=True, exist_ok=True)

    members = workspace_crates()
    checksums = lock_checksums(args.lock) if args.lock else {}
    ok = True
    for spec in args.crates or DEFAULT_CRATES:
        name, _, version = spec.partition("@")
        if name not in members:
            print(f"FAIL {name}: not a member of this workspace")
            ok = False
            continue
        ok &= compare(name, version, args, members, checksums)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

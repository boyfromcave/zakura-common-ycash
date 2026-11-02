#!/usr/bin/env python3
"""List CI features with the default cryptographic implementations selected."""
import json
import os
import subprocess
import sys

# zakura-common-ycash (2026-11-01): the fork's `ycash` feature swaps the Zcash
# consensus parameters for Ycash's, so "all supported features" leaves it out
# and stays upstream's Zcash build. CI's ycash legs set YCASH_FEATURE=on to add
# it (.github/README-ycash.md).
YCASH_FEATURE = "ycash"


def supported_features(metadata, selected, ycash=False):
    members = set(metadata["workspace_members"])
    defaults = {"backend-halo2", "pallas-pasta"}
    packages = [package for package in metadata["packages"]
                if package["id"] in members
                and ("--workspace" in selected or package["name"] in selected)]
    if not packages:
        raise ValueError("no workspace packages found for the selection")
    return sorted(
        f"{package['name']}/{feature}"
        for package in packages
        for feature in package["features"]
        if (not feature.startswith(("backend-", "pallas-")) or feature in defaults)
        and (ycash or feature != YCASH_FEATURE)
    )


if __name__ == "__main__":
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"
    ], text=True))
    try:
        features = supported_features(
            metadata, set(sys.argv[1:]),
            ycash=os.environ.get("YCASH_FEATURE", "off") == "on")
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(",".join(features))

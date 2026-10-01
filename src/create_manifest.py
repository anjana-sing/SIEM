import argparse
import csv
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

METADATA_FILE = Path("metadata/metadata.yaml")
MANIFEST_ROOT = Path("generated/manifests")
SUPPORTED_SIEMS = ("splunk", "sentinel", "chronicle")


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def latest_version(lookup_id):
    versions = []
    for root in (
        Path("generated/lookups") / lookup_id,
        Path("generated/metadata") / lookup_id,
        Path("generated/schema") / lookup_id,
        Path("generated/mapping") / lookup_id,
    ):
        if not root.exists():
            continue
        for p in root.iterdir():
            m = re.fullmatch(r"v(\d+)", p.name)
            if m and p.is_dir():
                versions.append(int(m.group(1)))
    if not versions:
        raise RuntimeError(f"{lookup_id}: no generated version found")
    return f"v{max(versions)}"


def target_file(lookup_id, siem, target_name):
    ext = "json" if siem == "chronicle" else "csv"
    return Path("generated") / siem / lookup_id / f"{target_name}.{ext}"


def csv_rows(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def json_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_manifest(lookup, source_sha, mode):
    lookup_id = lookup["lookup_id"]
    name = lookup["name"]
    version = latest_version(lookup_id)
    canonical = Path("lookups") / f"{name}.csv"

    if not canonical.exists():
        raise RuntimeError(f"{lookup_id}: canonical file not found: {canonical}")

    manifest = {
        "manifest_version": 1,
        "lookup_id": lookup_id,
        "lookup_name": name,
        "generation_version": version,
        "generation_mode": mode,
        "source_commit_sha": source_sha,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "canonical": {
            "path": str(canonical),
            "sha256": sha256_file(canonical),
        },
        "configuration_snapshot": {
            "deployment_config": (
                {
                    "path": str(Path("config/deployment.yaml")),
                    "sha256": sha256_file(Path("config/deployment.yaml")),
                }
                if Path("config/deployment.yaml").exists()
                else None
            ),
            "versioned_files": [],
        },
        "targets": {},
        "deployment": {},
    }

    for root in (
        Path("generated/lookups") / lookup_id / version,
        Path("generated/metadata") / lookup_id / version,
        Path("generated/schema") / lookup_id / version,
        Path("generated/mapping") / lookup_id / version,
    ):
        if root.exists():
            for file_path in sorted(p for p in root.rglob("*") if p.is_file()):
                manifest["configuration_snapshot"]["versioned_files"].append({
                    "path": str(file_path),
                    "sha256": sha256_file(file_path),
                })

    for siem in SUPPORTED_SIEMS:
        target = (lookup.get("targets") or {}).get(siem) or {}
        if not target.get("enabled", False):
            continue
        target_name = target.get("lookup_name")
        if not target_name:
            raise RuntimeError(f"{lookup_id}/{siem}: target lookup_name is required")
        path = target_file(lookup_id, siem, target_name)
        if not path.exists():
            raise RuntimeError(f"{lookup_id}/{siem}: generated target not found: {path}")
        manifest["targets"][siem] = {
            "lookup_name": target_name,
            "path": str(path),
            "sha256": sha256_file(path),
            "row_count": len(json_rows(path)) if siem == "chronicle" else len(csv_rows(path)),
        }
        manifest["deployment"][siem] = {
            "status": "pending",
            "http_status": None,
            "message": None,
        }

    return manifest


def write_manifest(manifest):
    path = MANIFEST_ROOT / manifest["lookup_id"] / f"{manifest['generation_version']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Manifest: {path}")
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lookup-id", action="append", required=True)
    parser.add_argument("--modes-json", required=True)
    parser.add_argument("--source-sha", default=os.environ.get("GENERATION_SHA", ""))
    args = parser.parse_args()

    try:
        modes = json.loads(args.modes_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("--modes-json must be valid JSON") from exc
    if not isinstance(modes, dict):
        raise RuntimeError("--modes-json must be a JSON object")
    if any(mode not in ("input", "canonical") for mode in modes.values()):
        raise RuntimeError("--modes-json values must be input or canonical")

    metadata = load_yaml(METADATA_FILE)
    by_id = {x.get("lookup_id"): x for x in metadata.get("lookups", [])}
    for lookup_id in dict.fromkeys(args.lookup_id):
        lookup = by_id.get(lookup_id)
        if not lookup:
            raise RuntimeError(f"{lookup_id}: not found in metadata")
        mode = modes.get(lookup_id)
        if mode is None:
            raise RuntimeError(f"{lookup_id}: generation mode missing from --modes-json")
        write_manifest(build_manifest(lookup, args.source_sha, mode))


if __name__ == "__main__":
    main()

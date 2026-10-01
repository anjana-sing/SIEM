import json
import os
import re
import subprocess
from pathlib import Path

import yaml


METADATA_FILE = Path("metadata/metadata.yaml")
CHANGED_FILES_FILE = Path("changed_files.txt")


# ================================================================
# YAML helpers
# ================================================================

def load_yaml_file(path):
    with open(path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def load_yaml_text(text):
    return yaml.safe_load(text) or {}


# ================================================================
# Metadata
# ================================================================

def load_metadata():

    if not METADATA_FILE.exists():
        raise RuntimeError(
            "metadata/metadata.yaml not found"
        )

    return load_yaml_file(
        METADATA_FILE
    )


def get_metadata_lookups(metadata):

    return {
        item.get("lookup_id"): item
        for item in metadata.get(
            "lookups",
            []
        )
        if item.get("lookup_id")
    }


# ================================================================
# Git
# ================================================================

def get_base_file_content(path):

    base_sha = os.environ.get(
        "BASE_SHA"
    )

    if not base_sha:
        return None

    try:

        result = subprocess.run(
            [
                "git",
                "show",
                f"{base_sha}:{path}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout

    except subprocess.CalledProcessError:

        # File did not exist in base branch.
        return None


def get_current_file_content(path):

    file_path = Path(path)

    if not file_path.exists():
        return None

    return file_path.read_text(
        encoding="utf-8"
    )


# ================================================================
# Extract lookup entries
# ================================================================

def extract_lookup_entries(data):

    """
    Supports:

    lookups:
      - lookup_id: LKP-001

    mappings:
      - lookup_id: LKP-001
    """

    entries = {}

    if not isinstance(data, dict):
        return entries

    # ------------------------------------------------------------
    # schema
    # ------------------------------------------------------------

    if isinstance(
        data.get("lookups"),
        list
    ):

        for item in data["lookups"]:

            if not isinstance(
                item,
                dict
            ):
                continue

            lookup_id = item.get(
                "lookup_id"
            )

            if lookup_id:
                entries[
                    lookup_id
                ] = item

    # ------------------------------------------------------------
    # mapping
    # ------------------------------------------------------------

    if isinstance(
        data.get("mappings"),
        list
    ):

        for item in data["mappings"]:

            if not isinstance(
                item,
                dict
            ):
                continue

            lookup_id = item.get(
                "lookup_id"
            )

            if lookup_id:
                entries[
                    lookup_id
                ] = item

    return entries


# ================================================================
# Detect changed lookup entries
# ================================================================

def detect_changed_yaml_lookups(
    path,
    valid_lookup_ids
):

    current_content = (
        get_current_file_content(path)
    )

    base_content = (
        get_base_file_content(path)
    )

    current_data = (
        load_yaml_text(current_content)
        if current_content
        else {}
    )

    base_data = (
        load_yaml_text(base_content)
        if base_content
        else {}
    )

    current_entries = (
        extract_lookup_entries(
            current_data
        )
    )

    base_entries = (
        extract_lookup_entries(
            base_data
        )
    )

    changed_ids = set()

    all_ids = (
        set(current_entries.keys())
        |
        set(base_entries.keys())
    )

    for lookup_id in all_ids:

        if lookup_id not in valid_lookup_ids:
            continue

        current = current_entries.get(
            lookup_id
        )

        base = base_entries.get(
            lookup_id
        )

        if current != base:

            changed_ids.add(
                lookup_id
            )

    return changed_ids


# ================================================================
# Canonical lookup
# ================================================================

def detect_canonical_lookup(
    path,
    lookup_by_name
):

    filename = Path(path).name

    lookup_name = Path(
        filename
    ).stem

    lookup_id = lookup_by_name.get(
        lookup_name
    )

    if lookup_id:
        return {lookup_id}

    return set()


# ================================================================
# Source file
# ================================================================

def build_source_index(lookups):

    source_index = {}

    for lookup in lookups.values():

        lookup_id = lookup.get(
            "lookup_id"
        )

        sources = lookup.get(
            "sources",
            {}
        )

        if not isinstance(
            sources,
            dict
        ):
            continue

        for source in sources.values():

            if not isinstance(
                source,
                dict
            ):
                continue

            source_file = source.get(
                "file"
            )

            if source_file:

                normalized = (
                    str(source_file)
                    .lstrip("./")
                )

                source_index[
                    normalized
                ] = lookup_id

    return source_index


# ================================================================
# Direct LKP path
# ================================================================

def detect_lookup_from_path(
    path,
    valid_lookup_ids
):

    matches = re.findall(
        r"LKP-\d+",
        path
    )

    return {
        item
        for item in matches
        if item in valid_lookup_ids
    }


# ================================================================
# ================================================================
# Main
# ================================================================

def main():
    print("======================================")
    print("Lookup detection started")
    print("======================================")

    metadata = load_metadata()
    metadata_lookups = get_metadata_lookups(metadata)
    valid_lookup_ids = set(metadata_lookups.keys())
    lookup_by_name = {
        lookup.get("name"): lookup_id
        for lookup_id, lookup in metadata_lookups.items()
        if lookup.get("name")
    }
    source_index = build_source_index(metadata_lookups)

    print("")
    print("Registered lookups:")
    for lookup_id, lookup in metadata_lookups.items():
        print(f"  {lookup_id} -> {lookup.get('name')}")

    if not CHANGED_FILES_FILE.exists():
        raise RuntimeError("changed_files.txt not found")

    changed_files = [
        line.strip()
        for line in CHANGED_FILES_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    print("")
    print("Changed files:")
    for path in changed_files:
        print(f"  {path}")

    affected = set()
    input_changed_ids = set()
    canonical_changed_ids = set()
    structural_changed_ids = set()

    print("")
    print("Resolution:")
    print("--------------------------------------")

    for changed_file in changed_files:
        path = changed_file.lstrip("./")

        # 1. Canonical lookup file changed.
        if path.startswith("lookups/"):
            resolved = detect_canonical_lookup(path, lookup_by_name)
            for lookup_id in resolved:
                lookup = metadata_lookups[lookup_id]
                canonical = lookup.get("canonical", {}) or {}
                if canonical.get("enabled", False):
                    affected.add(lookup_id)
                    canonical_changed_ids.add(lookup_id)
                    print(f"{path} -> {lookup_id} [canonical changed]")
                else:
                    print(f"{path} -> {lookup_id} [canonical disabled]")
            if not resolved:
                print(f"{path} -> NOT FOUND")
            continue

        # 2. Input/source file changed.
        if path.startswith("input/files/"):
            lookup_id = source_index.get(path)
            if lookup_id:
                affected.add(lookup_id)
                input_changed_ids.add(lookup_id)
                print(f"{path} -> {lookup_id} [input changed]")
            else:
                print(f"{path} -> NOT FOUND")
            continue

        # 3. Schema changed.
        if path.startswith("schema/"):
            changed_ids = detect_changed_yaml_lookups(path, valid_lookup_ids)
            if changed_ids:
                for lookup_id in sorted(changed_ids):
                    affected.add(lookup_id)
                    structural_changed_ids.add(lookup_id)
                    print(f"{path} -> {lookup_id} [schema changed]")
            else:
                print(f"{path} -> NO LOOKUP CONTENT CHANGED")
            continue

        # 4. Mapping changed.
        if path.startswith("mapping/"):
            changed_ids = detect_changed_yaml_lookups(path, valid_lookup_ids)
            if changed_ids:
                for lookup_id in sorted(changed_ids):
                    affected.add(lookup_id)
                    structural_changed_ids.add(lookup_id)
                    print(f"{path} -> {lookup_id} [mapping changed]")
            else:
                print(f"{path} -> NO LOOKUP CONTENT CHANGED")
            continue

        # 5. Global deployment configuration changed.
        if path == "config/deployment.yaml":
            for lookup_id in sorted(valid_lookup_ids):
                lookup = metadata_lookups[lookup_id]
                targets = lookup.get("targets", {}) or {}
                if any(
                    isinstance(targets.get(siem), dict)
                    and targets.get(siem, {}).get("enabled", False)
                    for siem in ("splunk", "sentinel", "chronicle")
                ):
                    affected.add(lookup_id)
                    structural_changed_ids.add(lookup_id)
                    print(f"{path} -> {lookup_id} [deployment configuration changed]")
            continue

        # 6. Metadata changed.
        if path == "metadata/metadata.yaml":
            changed_ids = detect_changed_yaml_lookups(path, valid_lookup_ids)
            if changed_ids:
                for lookup_id in sorted(changed_ids):
                    affected.add(lookup_id)
                    structural_changed_ids.add(lookup_id)
                    print(f"{path} -> {lookup_id} [metadata changed]")
            else:
                print(f"{path} -> NO LOOKUP CONTENT CHANGED")
            continue

        # 7. Any explicit LKP path.
        path_lookup_ids = detect_lookup_from_path(path, valid_lookup_ids)
        for lookup_id in path_lookup_ids:
            affected.add(lookup_id)
            structural_changed_ids.add(lookup_id)
            print(f"{path} -> {lookup_id} [path]")

    def sort_lookup_id(value):
        match = re.search(r"LKP-(\d+)", value)
        return int(match.group(1)) if match else 999999

    lookup_ids = sorted(affected, key=sort_lookup_id)
    lookup_ids_csv = ",".join(lookup_ids)
    lookup_ids_json = json.dumps(lookup_ids)

    # Generation mode is per Lookup ID.
    # Precedence:
    #   1. input file changed -> input
    #   2. canonical file changed -> canonical
    #   3. schema/mapping/metadata/config changed -> canonical if it exists,
    #      otherwise input
    # Therefore an updated input wins even when canonical already exists.
    lookup_modes = {}
    print("")
    print("Mode resolution:")
    for lookup_id in lookup_ids:
        lookup = metadata_lookups[lookup_id]
        lookup_name = lookup.get("name")
        canonical_path = Path("lookups") / f"{lookup_name}.csv" if lookup_name else None
        canonical_exists = bool(canonical_path and canonical_path.is_file())

        if lookup_id in input_changed_ids:
            mode = "input"
            reason = "input changed"
        elif lookup_id in canonical_changed_ids:
            mode = "canonical"
            reason = "canonical changed"
        elif canonical_exists:
            mode = "canonical"
            reason = "canonical exists"
        else:
            mode = "input"
            reason = "canonical missing"

        lookup_modes[lookup_id] = mode
        print(f"  {lookup_id} -> {mode} [{reason}]")

    print("")
    print("======================================")
    print("Affected Lookup IDs")
    print("======================================")
    if lookup_ids:
        for lookup_id in lookup_ids:
            print(f"  {lookup_id}")
    else:
        print("  No affected lookup IDs")
    print("======================================")
    print(f"CSV: {lookup_ids_csv}")
    print(f"JSON: {lookup_ids_json}")
    print(f"Lookup modes: {json.dumps(lookup_modes, sort_keys=True)}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as output:
            output.write(f"lookup_ids={lookup_ids_csv}\n")
            output.write("lookup_ids_json<<EOF\n")
            output.write(lookup_ids_json + "\n")
            output.write("EOF\n")
            output.write(f"lookup_count={len(lookup_ids)}\n")
            output.write("lookup_modes_json<<EOF\n")
            output.write(json.dumps(lookup_modes, sort_keys=True) + "\n")
            output.write("EOF\n")


if __name__ == "__main__":
    main()

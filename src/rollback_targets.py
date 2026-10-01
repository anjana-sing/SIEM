import argparse
import csv
import json
import re
import sys
from pathlib import Path

import yaml


GENERATED_DIR = Path("generated")

GENERATED_LOOKUPS_DIR = GENERATED_DIR / "lookups"
GENERATED_METADATA_DIR = GENERATED_DIR / "metadata"
GENERATED_SCHEMA_DIR = GENERATED_DIR / "schema"
GENERATED_MAPPING_DIR = GENERATED_DIR / "mapping"

GENERATED_SPLUNK_DIR = GENERATED_DIR / "splunk"
GENERATED_SENTINEL_DIR = GENERATED_DIR / "sentinel"
GENERATED_CHRONICLE_DIR = GENERATED_DIR / "chronicle"

SUPPORTED_SIEMS = (
    "splunk",
    "sentinel",
    "chronicle",
)


# ================================================================
# Helpers
# ================================================================

def load_yaml(path):
    if not path.exists():
        raise ValueError(
            f"Required file not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)

    return data or {}


def validate_version(
    version,
):
    if not re.fullmatch(
        r"v\d+",
        version,
    ):
        raise ValueError(
            f"Invalid version '{version}'. "
            f"Expected format vN, for example v1."
        )


def get_version_directory(
    base_directory,
    lookup_id,
    version,
):
    directory = (
        base_directory
        /
        lookup_id
        /
        version
    )

    if not directory.exists():

        raise ValueError(
            f"Versioned directory not found: "
            f"{directory}"
        )

    if not directory.is_dir():

        raise ValueError(
            f"Expected directory but found: "
            f"{directory}"
        )

    return directory


# ================================================================
# Load versioned source/configuration
# ================================================================

def load_versioned_metadata(
    lookup_id,
    version,
):
    directory = get_version_directory(
        GENERATED_METADATA_DIR,
        lookup_id,
        version,
    )

    path = (
        directory
        /
        "metadata.yaml"
    )

    return load_yaml(path)


def load_versioned_schema(
    lookup_id,
    version,
):
    directory = get_version_directory(
        GENERATED_SCHEMA_DIR,
        lookup_id,
        version,
    )

    path = (
        directory
        /
        "schema.yaml"
    )

    return load_yaml(path)


def load_versioned_mappings(
    lookup_id,
    version,
):
    directory = get_version_directory(
        GENERATED_MAPPING_DIR,
        lookup_id,
        version,
    )

    mappings = []

    for path in sorted(
        directory.glob("*.yaml")
    ):

        data = load_yaml(path)

        for mapping in data.get(
            "mappings",
            [],
        ):

            if mapping.get(
                "lookup_id"
            ) == lookup_id:

                mappings.append(
                    {
                        "file": path,
                        "mapping": mapping,
                    }
                )

    return mappings


def read_versioned_canonical(
    lookup_id,
    version,
    lookup_name,
):
    directory = get_version_directory(
        GENERATED_LOOKUPS_DIR,
        lookup_id,
        version,
    )

    path = (
        directory
        /
        f"{lookup_name}.csv"
    )

    if not path.exists():

        raise ValueError(
            f"Versioned canonical lookup not found: "
            f"{path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(
            file
        )

        if not reader.fieldnames:

            raise ValueError(
                f"{path}: no CSV header"
            )

        fields = [
            field.strip()
            for field in reader.fieldnames
        ]

        rows = []

        for row in reader:

            cleaned = {}

            for key, value in row.items():

                cleaned[key.strip()] = (
                    value.strip()
                    if isinstance(
                        value,
                        str,
                    )
                    else value
                )

            rows.append(cleaned)

    return fields, rows


# ================================================================
# Mapping helpers
# ================================================================

def get_mapping(
    mappings,
    siem,
):
    for item in mappings:

        mapping = item["mapping"]

        if mapping.get(
            "siem"
        ) == siem:

            return mapping

    return None


def resolve_mapping_target(
    target,
):
    if not isinstance(
        target,
        str,
    ):
        return target

    target = target.strip()

    if "." in target:

        parts = target.split(".")

        if len(parts) == 2:

            return (
                f"{parts[0]}_{parts[1]}"
            )

    return target


def generate_rows(
    canonical_rows,
    mapping,
    target_fields,
):
    field_mapping = mapping.get(
        "fields",
        {}
    )

    defaults = mapping.get(
        "defaults",
        {}
    )

    generated_rows = []

    for canonical_row in canonical_rows:

        target_row = {}

        for target_field, canonical_field in (
            field_mapping.items()
        ):

            resolved_field = (
                resolve_mapping_target(
                    canonical_field
                )
            )

            target_row[target_field] = (
                canonical_row.get(
                    resolved_field,
                    "",
                )
            )

        for field_name, default_value in (
            defaults.items()
        ):

            if (
                field_name not in target_row
                or
                target_row[field_name] in (
                    None,
                    "",
                )
            ):

                target_row[field_name] = (
                    default_value
                )

        for field_name in target_fields:

            target_row.setdefault(
                field_name,
                "",
            )

        generated_rows.append(
            target_row
        )

    return generated_rows


def get_target_fields(
    mapping,
):
    fields = list(
        mapping.get(
            "fields",
            {}
        ).keys()
    )

    for field in mapping.get(
        "defaults",
        {}
    ).keys():

        if field not in fields:
            fields.append(field)

    return fields


# ================================================================
# Output helpers
# ================================================================

def write_csv(
    path,
    fields,
    rows,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()

        for row in rows:

            writer.writerow(
                {
                    field: row.get(
                        field,
                        "",
                    )
                    for field in fields
                }
            )


def write_json(
    path,
    rows,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            rows,
            file,
            indent=2,
        )

        file.write("\n")


# ================================================================
# Rollback one SIEM
# ================================================================

def rollback_siem(
    lookup_id,
    siem,
    target,
    canonical_rows,
    mappings,
):
    mapping = get_mapping(
        mappings,
        siem,
    )

    if not mapping:

        raise ValueError(
            f"{lookup_id}/{siem}: "
            f"no mapping found in selected version"
        )

    target_lookup_name = target.get(
        "lookup_name"
    )

    if not target_lookup_name:

        raise ValueError(
            f"{lookup_id}/{siem}: "
            f"target lookup_name is required"
        )

    target_fields = get_target_fields(
        mapping
    )

    if not target_fields:

        raise ValueError(
            f"{lookup_id}/{siem}: "
            f"mapping contains no fields"
        )

    generated_rows = generate_rows(
        canonical_rows,
        mapping,
        target_fields,
    )

    if siem == "splunk":

        output_file = (
            GENERATED_SPLUNK_DIR
            /
            lookup_id
            /
            f"{target_lookup_name}.csv"
        )

        write_csv(
            output_file,
            target_fields,
            generated_rows,
        )

    elif siem == "sentinel":

        output_file = (
            GENERATED_SENTINEL_DIR
            /
            lookup_id
            /
            f"{target_lookup_name}.csv"
        )

        write_csv(
            output_file,
            target_fields,
            generated_rows,
        )

    elif siem == "chronicle":

        output_file = (
            GENERATED_CHRONICLE_DIR
            /
            lookup_id
            /
            f"{target_lookup_name}.json"
        )

        write_json(
            output_file,
            generated_rows,
        )

    else:

        raise ValueError(
            f"Unsupported SIEM: {siem}"
        )

    print(
        f"Rolled back {siem}: "
        f"{output_file}"
    )

    print(
        f"Rows restored: "
        f"{len(generated_rows)}"
    )


# ================================================================
# Rollback one lookup
# ================================================================

def rollback_lookup(
    lookup_id,
    version,
):
    validate_version(
        version
    )

    print(
        "======================================"
    )

    print(
        f"Rollback {lookup_id} -> {version}"
    )

    print(
        "======================================"
    )

    # ------------------------------------------------------------
    # Load ONLY versioned artifacts.
    #
    # Root metadata/schema/mapping are deliberately not used.
    # ------------------------------------------------------------

    metadata_document = load_versioned_metadata(
        lookup_id,
        version,
    )

    schema_document = load_versioned_schema(
        lookup_id,
        version,
    )

    mappings = load_versioned_mappings(
        lookup_id,
        version,
    )

    # Ensure the requested lookup exists in snapshots.
    metadata = None

    for item in metadata_document.get(
        "lookups",
        [],
    ):

        if item.get(
            "lookup_id"
        ) == lookup_id:

            metadata = item
            break

    if not metadata:

        raise ValueError(
            f"{lookup_id}: lookup not found in "
            f"versioned metadata"
        )

    schema = None

    for item in schema_document.get(
        "lookups",
        [],
    ):

        if item.get(
            "lookup_id"
        ) == lookup_id:

            schema = item
            break

    if not schema:

        raise ValueError(
            f"{lookup_id}: lookup not found in "
            f"versioned schema"
        )

    lookup_name = metadata.get(
        "name"
    )

    if not lookup_name:

        raise ValueError(
            f"{lookup_id}: versioned metadata "
            f"does not contain name"
        )

    # ------------------------------------------------------------
    # Read canonical snapshot
    # ------------------------------------------------------------

    fields, canonical_rows = (
        read_versioned_canonical(
            lookup_id,
            version,
            lookup_name,
        )
    )

    print(
        f"Versioned canonical: "
        f"generated/lookups/{lookup_id}/{version}/"
        f"{lookup_name}.csv"
    )

    print(
        f"Canonical rows: "
        f"{len(canonical_rows)}"
    )

    print(
        f"Versioned schema fields: "
        f"{len(schema.get('common_fields', {}))}"
    )

    # ------------------------------------------------------------
    # Restore enabled targets
    # ------------------------------------------------------------

    targets = metadata.get(
        "targets",
        {}
    )

    for siem in SUPPORTED_SIEMS:

        target = targets.get(
            siem,
            {}
        )

        if not target.get(
            "enabled",
            False,
        ):
            continue

        rollback_siem(
            lookup_id,
            siem,
            target,
            canonical_rows,
            mappings,
        )

    print(
        f"{lookup_id}: rollback to "
        f"{version} completed"
    )


# ================================================================
# CLI
# ================================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "Rollback generated SIEM lookups "
            "to a previously versioned snapshot."
        )
    )

    parser.add_argument(
        "--lookup-id",
        required=True,
        help="Lookup ID, for example LKP-001",
    )

    parser.add_argument(
        "--version",
        required=True,
        help="Version to restore, for example v1",
    )

    return parser.parse_args()


# ================================================================
# Main
# ================================================================

def main():

    args = parse_args()

    rollback_lookup(
        args.lookup_id,
        args.version,
    )


# ================================================================
# Entry point
# ================================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as exc:

        print("")

        print(
            "======================================"
        )

        print(
            "ROLLBACK FAILED"
        )

        print(
            "======================================"
        )

        print(
            str(exc)
        )

        print(
            "======================================"
        )

        sys.exit(1)

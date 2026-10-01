import csv
import json
import os
import re
import shutil
import sys
from pathlib import Path

import yaml


METADATA_FILE = Path("metadata/metadata.yaml")
SCHEMA_FILE = Path("schema/schema.yaml")
MAPPING_DIR = Path("mapping")
LOOKUP_DIR = Path("lookups")
GENERATED_DIR = Path("generated")

# Versioned source/config snapshots
GENERATED_LOOKUPS_DIR = GENERATED_DIR / "lookups"
GENERATED_METADATA_DIR = GENERATED_DIR / "metadata"
GENERATED_SCHEMA_DIR = GENERATED_DIR / "schema"
GENERATED_MAPPING_DIR = GENERATED_DIR / "mapping"

# Current generated SIEM outputs - intentionally NOT versioned
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


def get_affected_ids():
    value = os.environ.get(
        "LOOKUP_IDS_JSON",
        "[]",
    )

    try:
        ids = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "LOOKUP_IDS_JSON is invalid JSON"
        ) from exc

    if not isinstance(ids, list):
        raise ValueError(
            "LOOKUP_IDS_JSON must be a list"
        )

    result = []

    for lookup_id in ids:
        if lookup_id not in result:
            result.append(lookup_id)

    return result


# ================================================================
# Version helpers
# ================================================================

def get_existing_version_numbers(
    base_directory,
    lookup_id,
):
    """
    Return existing numeric versions for:

        generated/<artifact>/<lookup_id>/vN
    """

    lookup_directory = (
        base_directory
        / lookup_id
    )

    if not lookup_directory.exists():
        return []

    version_numbers = []

    for path in lookup_directory.iterdir():

        if not path.is_dir():
            continue

        match = re.fullmatch(
            r"v(\d+)",
            path.name,
        )

        if match:
            version_numbers.append(
                int(match.group(1))
            )

    return version_numbers


def get_common_version(
    lookup_id,
):
    """
    Allocate one shared version across:

        generated/lookups/<lookup_id>
        generated/metadata/<lookup_id>
        generated/schema/<lookup_id>
        generated/mapping/<lookup_id>

    Example:

        none exists -> v1
        v1 exists   -> v2
        v1,v2 exist -> v3
    """

    version_numbers = []

    for base_directory in (
        GENERATED_LOOKUPS_DIR,
        GENERATED_METADATA_DIR,
        GENERATED_SCHEMA_DIR,
        GENERATED_MAPPING_DIR,
    ):
        version_numbers.extend(
            get_existing_version_numbers(
                base_directory,
                lookup_id,
            )
        )

    if not version_numbers:
        return "v1"

    return f"v{max(version_numbers) + 1}"


def create_version_directory(
    base_directory,
    lookup_id,
    version,
):
    directory = (
        base_directory
        / lookup_id
        / version
    )

    if directory.exists():
        raise ValueError(
            f"Version directory already exists: "
            f"{directory}"
        )

    directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    return directory


# ================================================================
# Metadata
# ================================================================

def load_metadata():

    data = load_yaml(
        METADATA_FILE
    )

    result = {}

    for lookup in data.get(
        "lookups",
        [],
    ):

        lookup_id = lookup.get(
            "lookup_id"
        )

        if lookup_id:
            result[lookup_id] = lookup

    return result


# ================================================================
# Schema
# ================================================================

def load_schema():

    data = load_yaml(
        SCHEMA_FILE
    )

    result = {}

    for lookup in data.get(
        "lookups",
        [],
    ):

        lookup_id = lookup.get(
            "lookup_id"
        )

        if lookup_id:
            result[lookup_id] = lookup

    return result


# ================================================================
# Mapping
# ================================================================

def load_mappings():

    result = {}

    if not MAPPING_DIR.exists():
        return result

    for path in sorted(
        MAPPING_DIR.glob("*.yaml")
    ):

        data = load_yaml(
            path
        )

        for mapping in data.get(
            "mappings",
            [],
        ):

            lookup_id = mapping.get(
                "lookup_id"
            )

            if not lookup_id:
                continue

            result.setdefault(
                lookup_id,
                [],
            ).append(
                {
                    "file": path,
                    "mapping": mapping,
                }
            )

    return result


# ================================================================
# Canonical field helpers
# ================================================================

def canonical_field_name(
    siem,
    field_name,
):
    return f"{siem}_{field_name}"


def get_canonical_schema_fields(
    schema,
):

    fields = {}

    # Common fields
    for field_name, definition in schema.get(
        "common_fields",
        {},
    ).items():

        fields[field_name] = definition

    # SIEM-specific fields
    for siem, siem_fields in schema.get(
        "siem_specific_fields",
        {},
    ).items():

        if not isinstance(
            siem_fields,
            dict,
        ):
            continue

        for field_name, definition in siem_fields.items():

            prefixed_name = canonical_field_name(
                siem,
                field_name,
            )

            fields[prefixed_name] = definition

    return fields


def get_canonical_field_names(
    schema,
):

    return list(
        get_canonical_schema_fields(
            schema
        ).keys()
    )


# ================================================================
# Canonical lookup
# ================================================================

def read_canonical_lookup(
    lookup_name,
):

    path = (
        LOOKUP_DIR
        /
        f"{lookup_name}.csv"
    )

    if not path.exists():

        raise ValueError(
            f"Canonical lookup not found: "
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

        if len(fields) != len(
            set(fields)
        ):

            raise ValueError(
                f"{path}: duplicate CSV fields"
            )

        rows = []

        for row in reader:

            cleaned = {}

            for key, value in row.items():

                clean_key = key.strip()

                cleaned[clean_key] = (
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
# Type validation
# ================================================================

def validate_type(
    value,
    field_name,
    definition,
    location,
):

    if value in (
        None,
        "",
    ):
        return

    field_type = definition.get(
        "type"
    )

    value_string = str(
        value
    ).strip()

    if field_type == "string":
        return

    if field_type == "integer":

        try:
            int(value_string)

        except ValueError:

            raise ValueError(
                f"{location}: field "
                f"'{field_name}' must be integer, "
                f"got '{value}'"
            )

        return

    if field_type == "date":

        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}"
            r"(T.*)?",
            value_string,
        ):

            raise ValueError(
                f"{location}: field "
                f"'{field_name}' must be "
                f"YYYY-MM-DD or ISO datetime, "
                f"got '{value}'"
            )

        return

    raise ValueError(
        f"{location}: unsupported "
        f"schema type '{field_type}'"
    )


# ================================================================
# Validate canonical lookup
# ================================================================

def validate_canonical(
    lookup_id,
    rows,
    fields,
    schema,
):

    schema_fields = (
        get_canonical_schema_fields(
            schema
        )
    )

    expected_fields = set(
        schema_fields.keys()
    )

    actual_fields = set(
        fields
    )

    missing_fields = (
        expected_fields
        -
        actual_fields
    )

    if missing_fields:

        raise ValueError(
            f"{lookup_id}: canonical lookup "
            f"is missing schema fields: "
            f"{sorted(missing_fields)}"
        )

    unknown_fields = (
        actual_fields
        -
        expected_fields
    )

    if unknown_fields:

        raise ValueError(
            f"{lookup_id}: canonical lookup "
            f"contains unknown fields: "
            f"{sorted(unknown_fields)}"
        )

    for row_number, row in enumerate(
        rows,
        start=2,
    ):

        for field_name, definition in (
            schema_fields.items()
        ):

            if not isinstance(
                definition,
                dict,
            ):
                continue

            value = row.get(
                field_name,
                "",
            )

            required = definition.get(
                "required",
                False,
            )

            if (
                required
                and
                (
                    value is None
                    or
                    str(value).strip() == ""
                )
            ):

                raise ValueError(
                    f"{lookup_id}: canonical "
                    f"row {row_number}: "
                    f"required field "
                    f"'{field_name}' is empty"
                )

            validate_type(
                value,
                field_name,
                definition,
                f"{lookup_id}:row{row_number}",
            )


# ================================================================
# Find mapping
# ================================================================

def get_mapping(
    mappings,
    lookup_id,
    siem,
):

    for item in mappings.get(
        lookup_id,
        [],
    ):

        mapping = item["mapping"]

        if mapping.get("siem") == siem:
            return mapping

    return None


# ================================================================
# Resolve canonical field
# ================================================================

def resolve_mapping_target(
    target,
    siem=None,
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

            target_siem = parts[0]
            field_name = parts[1]

            return canonical_field_name(
                target_siem,
                field_name,
            )

    return target


# ================================================================
# Validate mapping
# ================================================================

def validate_mapping(
    lookup_id,
    siem,
    mapping,
    schema,
    metadata,
):

    if not mapping:

        raise ValueError(
            f"{lookup_id}: target '{siem}' "
            f"is enabled but no mapping exists"
        )

    mapping_name = mapping.get(
        "name"
    )

    metadata_name = metadata.get(
        "name"
    )

    if mapping_name != metadata_name:

        raise ValueError(
            f"{lookup_id}: mapping name "
            f"'{mapping_name}' does not match "
            f"metadata name "
            f"'{metadata_name}'"
        )

    canonical_schema_fields = (
        get_canonical_schema_fields(
            schema
        )
    )

    for target_field, canonical_field in (
        mapping.get(
            "fields",
            {},
        ).items()
    ):

        resolved_field = (
            resolve_mapping_target(
                canonical_field,
                siem,
            )
        )

        if resolved_field not in (
            canonical_schema_fields
        ):

            raise ValueError(
                f"{lookup_id}/{siem}: "
                f"mapping references "
                f"undefined canonical field "
                f"'{canonical_field}' "
                f"(resolved as "
                f"'{resolved_field}')"
            )

        if "." in str(
            canonical_field
        ):

            field_siem = str(
                canonical_field
            ).split(".")[0]

            if field_siem != siem:

                raise ValueError(
                    f"{lookup_id}/{siem}: "
                    f"mapping references "
                    f"SIEM-specific field "
                    f"'{canonical_field}' "
                    f"belonging to '{field_siem}'"
                )

    for field_name in mapping.get(
        "defaults",
        {},
    ).keys():

        resolved_field = (
            resolve_mapping_target(
                field_name,
                siem,
            )
        )

        if resolved_field not in (
            canonical_schema_fields
        ):

            raise ValueError(
                f"{lookup_id}/{siem}: "
                f"default references "
                f"undefined canonical field "
                f"'{field_name}'"
            )


# ================================================================
# Generate target rows
# ================================================================

def generate_rows(
    canonical_rows,
    mapping,
    target_fields,
    siem,
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
                    canonical_field,
                    siem,
                )
            )

            value = canonical_row.get(
                resolved_field,
                "",
            )

            target_row[target_field] = value

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


# ================================================================
# Determine target fields
# ================================================================

def get_target_fields(
    mapping,
):

    fields = list(
        mapping.get(
            "fields",
            {}
        ).keys()
    )

    defaults = list(
        mapping.get(
            "defaults",
            {}
        ).keys()
    )

    for field in defaults:

        if field not in fields:
            fields.append(field)

    return fields


# ================================================================
# Validate generated rows
# ================================================================

def validate_generated_rows(
    lookup_id,
    siem,
    rows,
    target_fields,
):

    expected_fields = set(
        target_fields
    )

    for row_number, row in enumerate(
        rows,
        start=2,
    ):

        actual_fields = set(
            row.keys()
        )

        missing_fields = (
            expected_fields
            -
            actual_fields
        )

        if missing_fields:

            raise ValueError(
                f"{lookup_id}/{siem}: "
                f"generated row {row_number} "
                f"is missing fields: "
                f"{sorted(missing_fields)}"
            )

        for field_name in target_fields:

            if field_name not in row:

                raise ValueError(
                    f"{lookup_id}/{siem}: "
                    f"generated row "
                    f"{row_number}: missing "
                    f"target field "
                    f"'{field_name}'"
                )


# ================================================================
# CSV output
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


# ================================================================
# JSON output
# ================================================================

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
# Version source/config artifacts
# ================================================================

def write_versioned_artifacts(
    lookup_id,
    lookup_name,
    mappings,
    version,
):
    """
    Snapshot the exact source/configuration used to generate
    this version.

    Versioned:

        generated/lookups/<lookup_id>/<version>/
        generated/metadata/<lookup_id>/<version>/
        generated/schema/<lookup_id>/<version>/
        generated/mapping/<lookup_id>/<version>/

    Not versioned:

        generated/splunk/
        generated/sentinel/
        generated/chronicle/
    """

    created_directories = []

    try:

        # --------------------------------------------------------
        # Create all version directories
        # --------------------------------------------------------

        lookup_directory = create_version_directory(
            GENERATED_LOOKUPS_DIR,
            lookup_id,
            version,
        )

        created_directories.append(
            lookup_directory
        )

        metadata_directory = create_version_directory(
            GENERATED_METADATA_DIR,
            lookup_id,
            version,
        )

        created_directories.append(
            metadata_directory
        )

        schema_directory = create_version_directory(
            GENERATED_SCHEMA_DIR,
            lookup_id,
            version,
        )

        created_directories.append(
            schema_directory
        )

        mapping_directory = create_version_directory(
            GENERATED_MAPPING_DIR,
            lookup_id,
            version,
        )

        created_directories.append(
            mapping_directory
        )

        # --------------------------------------------------------
        # Canonical lookup
        # --------------------------------------------------------

        canonical_source = (
            LOOKUP_DIR
            /
            f"{lookup_name}.csv"
        )

        if not canonical_source.exists():

            raise ValueError(
                f"Canonical lookup not found: "
                f"{canonical_source}"
            )

        canonical_destination = (
            lookup_directory
            /
            canonical_source.name
        )

        shutil.copy2(
            canonical_source,
            canonical_destination,
        )

        # --------------------------------------------------------
        # Metadata
        # --------------------------------------------------------

        metadata_destination = (
            metadata_directory
            /
            METADATA_FILE.name
        )

        shutil.copy2(
            METADATA_FILE,
            metadata_destination,
        )

        # --------------------------------------------------------
        # Schema
        # --------------------------------------------------------

        schema_destination = (
            schema_directory
            /
            SCHEMA_FILE.name
        )

        shutil.copy2(
            SCHEMA_FILE,
            schema_destination,
        )

        # --------------------------------------------------------
        # Mapping
        # --------------------------------------------------------

        mapping_items = mappings.get(
            lookup_id,
            []
        )

        if not mapping_items:

            raise ValueError(
                f"{lookup_id}: no mapping "
                f"configuration found"
            )

        for item in mapping_items:

            source = item["file"]

            destination = (
                mapping_directory
                /
                source.name
            )

            shutil.copy2(
                source,
                destination,
            )

        print(
            f"Versioned artifacts created: "
            f"{lookup_id}/{version}"
        )

        print(
            f"  {canonical_destination}"
        )

        print(
            f"  {metadata_destination}"
        )

        print(
            f"  {schema_destination}"
        )

        for item in mapping_items:

            print(
                f"  "
                f"{mapping_directory / item['file'].name}"
            )

    except Exception:

        # Remove only directories created during this operation.
        for directory in reversed(
            created_directories
        ):

            if directory.exists():

                shutil.rmtree(
                    directory
                )

        raise


# ================================================================
# Generate one SIEM
# ================================================================

def generate_siem(
    lookup_id,
    lookup_name,
    siem,
    metadata,
    schema,
    mappings,
    canonical_rows,
):

    target = (
        metadata.get(
            "targets",
            {}
        )
        .get(
            siem,
            {}
        )
    )

    if not target.get(
        "enabled",
        False,
    ):

        print(
            f"{lookup_id}: {siem} "
            f"target disabled"
        )

        return

    mapping = get_mapping(
        mappings,
        lookup_id,
        siem,
    )

    validate_mapping(
        lookup_id,
        siem,
        mapping,
        schema,
        metadata,
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
        siem,
    )

    validate_generated_rows(
        lookup_id,
        siem,
        generated_rows,
        target_fields,
    )

    target_lookup_name = target.get(
        "lookup_name"
    )

    if not target_lookup_name:

        raise ValueError(
            f"{lookup_id}/{siem}: "
            f"target lookup_name is required"
        )

    # ------------------------------------------------------------
    # SIEM output directories are NOT versioned.
    # ------------------------------------------------------------

    if siem == "splunk":

        output_directory = (
            GENERATED_SPLUNK_DIR
            /
            lookup_id
        )

        output_file = (
            output_directory
            /
            f"{target_lookup_name}.csv"
        )

        write_csv(
            output_file,
            target_fields,
            generated_rows,
        )

    elif siem == "sentinel":

        output_directory = (
            GENERATED_SENTINEL_DIR
            /
            lookup_id
        )

        output_file = (
            output_directory
            /
            f"{target_lookup_name}.csv"
        )

        write_csv(
            output_file,
            target_fields,
            generated_rows,
        )

    elif siem == "chronicle":

        output_directory = (
            GENERATED_CHRONICLE_DIR
            /
            lookup_id
        )

        output_file = (
            output_directory
            /
            f"{target_lookup_name}.json"
        )

        write_json(
            output_file,
            generated_rows,
        )

    else:

        raise ValueError(
            f"{lookup_id}: unsupported "
            f"target SIEM '{siem}'"
        )

    print(
        f"Generated {siem}: "
        f"{output_file}"
    )

    print(
        f"Generated rows: "
        f"{len(generated_rows)}"
    )


# ================================================================
# Process one lookup
# ================================================================

def process_lookup(
    lookup_id,
    metadata_by_id,
    schema_by_id,
    mappings,
):

    print(
        "======================================"
    )

    print(
        f"Processing {lookup_id}"
    )

    print(
        "======================================"
    )

    metadata = metadata_by_id.get(
        lookup_id
    )

    if not metadata:

        raise ValueError(
            f"{lookup_id}: not found "
            f"in metadata.yaml"
        )

    schema = schema_by_id.get(
        lookup_id
    )

    if not schema:

        raise ValueError(
            f"{lookup_id}: not found "
            f"in schema.yaml"
        )

    canonical = metadata.get(
        "canonical",
        {}
    )

    if not canonical.get(
        "enabled",
        False,
    ):

        print(
            f"{lookup_id}: canonical "
            f"generation disabled"
        )

        return

    lookup_name = metadata.get(
        "name"
    )

    if not lookup_name:

        raise ValueError(
            f"{lookup_id}: metadata "
            f"name is missing"
        )

    # ------------------------------------------------------------
    # Read canonical
    # ------------------------------------------------------------

    fields, canonical_rows = (
        read_canonical_lookup(
            lookup_name
        )
    )

    print(
        f"Canonical: "
        f"lookups/{lookup_name}.csv"
    )

    print(
        f"Canonical rows: "
        f"{len(canonical_rows)}"
    )

    # ------------------------------------------------------------
    # Validate canonical
    # ------------------------------------------------------------

    expected_fields = (
        get_canonical_field_names(
            schema
        )
    )

    print(
        "Canonical fields:"
    )

    for field in expected_fields:

        print(
            f"  {field}"
        )

    validate_canonical(
        lookup_id,
        canonical_rows,
        fields,
        schema,
    )

    print(
        f"{lookup_id}: canonical "
        f"validation passed"
    )

    # ------------------------------------------------------------
    # Validation-only mode is used for canonical-edit workflows.
    # Do not allocate a version or write any file in this mode.
    # ------------------------------------------------------------

    if os.environ.get("VALIDATE_ONLY") == "1":
        print(f"{lookup_id}: canonical validation completed; no files written")
        return

    # ------------------------------------------------------------
    # Allocate one shared version.
    #
    # Version is allocated only after validation succeeds.
    # ------------------------------------------------------------

    version = get_common_version(
        lookup_id
    )

    print(
        f"{lookup_id}: allocated "
        f"version {version}"
    )

    # ------------------------------------------------------------
    # Snapshot source/configuration.
    # ------------------------------------------------------------

    write_versioned_artifacts(
        lookup_id,
        lookup_name,
        mappings,
        version,
    )

    # ------------------------------------------------------------
    # Generate current SIEM outputs.
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

        generate_siem(
            lookup_id,
            lookup_name,
            siem,
            metadata,
            schema,
            mappings,
            canonical_rows,
        )

    print(
        f"{lookup_id}: generation "
        f"completed at {version}"
    )


# ================================================================
# Main
# ================================================================

def main():

    if "--validate-only" in sys.argv[1:]:
        os.environ["VALIDATE_ONLY"] = "1"

    print(
        "======================================"
    )

    print(
        "Target Lookup Generation"
    )

    print(
        "======================================"
    )

    affected_ids = get_affected_ids()

    if not affected_ids:

        print(
            "No affected lookup IDs."
        )

        return

    print(
        "Affected Lookup IDs:"
    )

    for lookup_id in affected_ids:

        print(
            f"  {lookup_id}"
        )

    print("")

    metadata_by_id = load_metadata()

    schema_by_id = load_schema()

    mappings = load_mappings()

    for lookup_id in affected_ids:

        process_lookup(
            lookup_id,
            metadata_by_id,
            schema_by_id,
            mappings,
        )

    print("")

    print(
        "======================================"
    )

    print(
        "Target generation completed"
    )

    print(
        "======================================")


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
            "GENERATION FAILED"
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

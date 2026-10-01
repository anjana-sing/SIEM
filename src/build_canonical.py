import csv
import json
import os
import re
import sys
from pathlib import Path

import yaml


METADATA_FILE = Path("metadata/metadata.yaml")
SCHEMA_FILE = Path("schema/schema.yaml")
MAPPING_DIR = Path("mapping")
INPUT_DIR = Path("input/files")
PROCESSED_MANIFEST = Path("processed_input_files.txt")
LOOKUP_DIR = Path("lookups")


# ================================================================
# Errors
# ================================================================

class ValidationError(Exception):
    pass


class ConflictError(Exception):
    pass


# ================================================================
# YAML helpers
# ================================================================

def load_yaml(path):

    if not path.exists():
        raise ValidationError(
            f"Required file not found: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        data = yaml.safe_load(file)

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValidationError(
            f"{path} must contain a YAML object"
        )

    return data


# ================================================================
# Affected IDs
# ================================================================

def get_affected_lookup_ids():

    value = os.environ.get(
        "LOOKUP_IDS_JSON",
        "[]"
    )

    try:

        ids = json.loads(value)

    except json.JSONDecodeError as exc:

        raise ValidationError(
            "LOOKUP_IDS_JSON contains invalid JSON"
        ) from exc

    if not isinstance(ids, list):

        raise ValidationError(
            "LOOKUP_IDS_JSON must be a JSON array"
        )

    for lookup_id in ids:

        if not isinstance(
            lookup_id,
            str
        ):

            raise ValidationError(
                "Every lookup ID must be a string"
            )

        if not re.fullmatch(
            r"LKP-\d+",
            lookup_id
        ):

            raise ValidationError(
                f"Invalid lookup ID: {lookup_id}"
            )

    return ids


# ================================================================
# Basic type validation
# ================================================================

def validate_value_type(
    value,
    field_name,
    definition,
    location
):

    if value is None:
        value = ""

    value = str(value).strip()

    if value == "":
        return

    field_type = definition.get(
        "type"
    )

    if field_type == "string":
        return

    if field_type == "integer":

        try:

            int(value)

        except ValueError:

            raise ValidationError(
                f"{location}: field "
                f"'{field_name}' must be integer, "
                f"got '{value}'"
            )

        return

    if field_type == "date":

        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}"
            r"(T.*)?",
            value
        ):

            raise ValidationError(
                f"{location}: field "
                f"'{field_name}' must be "
                f"YYYY-MM-DD or ISO datetime, "
                f"got '{value}'"
            )

        return

    raise ValidationError(
        f"{location}: unsupported type "
        f"'{field_type}' for field "
        f"'{field_name}'"
    )


# ================================================================
# Validate metadata
# ================================================================

def validate_metadata(
    metadata
):

    errors = []

    if "lookups" not in metadata:

        errors.append(
            "metadata.yaml must contain 'lookups'"
        )

        return errors

    if not isinstance(
        metadata["lookups"],
        list
    ):

        errors.append(
            "'lookups' must be a list"
        )

        return errors

    seen_ids = set()
    seen_names = set()

    for index, lookup in enumerate(
        metadata["lookups"]
    ):

        location = (
            f"metadata.lookups[{index}]"
        )

        if not isinstance(
            lookup,
            dict
        ):

            errors.append(
                f"{location} must be an object"
            )

            continue

        lookup_id = lookup.get(
            "lookup_id"
        )

        name = lookup.get(
            "name"
        )

        # --------------------------------------------------------
        # lookup_id
        # --------------------------------------------------------

        if not lookup_id:

            errors.append(
                f"{location}.lookup_id is required"
            )

        elif not re.fullmatch(
            r"LKP-\d+",
            str(lookup_id)
        ):

            errors.append(
                f"{location}.lookup_id "
                f"'{lookup_id}' is invalid"
            )

        elif lookup_id in seen_ids:

            errors.append(
                f"Duplicate lookup_id: "
                f"{lookup_id}"
            )

        else:

            seen_ids.add(
                lookup_id
            )

        # --------------------------------------------------------
        # name
        # --------------------------------------------------------

        if not name:

            errors.append(
                f"{location}.name is required"
            )

        elif name in seen_names:

            errors.append(
                f"Duplicate lookup name: "
                f"{name}"
            )

        else:

            seen_names.add(
                name
            )

        # --------------------------------------------------------
        # canonical
        # --------------------------------------------------------

        canonical = lookup.get(
            "canonical"
        )

        if not isinstance(
            canonical,
            dict
        ):

            errors.append(
                f"{location}.canonical "
                f"must be an object"
            )

        else:

            if not isinstance(
                canonical.get(
                    "enabled"
                ),
                bool
            ):

                errors.append(
                    f"{location}.canonical.enabled "
                    f"must be boolean"
                )

            if not canonical.get(
                "key"
            ):

                errors.append(
                    f"{location}.canonical.key "
                    f"is required"
                )

        # --------------------------------------------------------
        # sources
        # --------------------------------------------------------

        sources = lookup.get(
            "sources"
        )

        if not isinstance(
            sources,
            dict
        ):

            errors.append(
                f"{location}.sources "
                f"must be an object"
            )

        else:

            for source_name, source in (
                sources.items()
            ):

                if not isinstance(
                    source,
                    dict
                ):

                    errors.append(
                        f"{location}.sources."
                        f"{source_name} "
                        f"must be an object"
                    )

                    continue

                source_file = source.get(
                    "file"
                )

                if source_file is not None:

                    if not isinstance(
                        source_file,
                        str
                    ):

                        errors.append(
                            f"{location}.sources."
                            f"{source_name}.file "
                            f"must be string or null"
                        )

                    elif (
                        source_file
                        and
                        not source_file.startswith(
                            "input/files/"
                        )
                    ):

                        errors.append(
                            f"{location}.sources."
                            f"{source_name}.file "
                            f"must be under "
                            f"input/files/"
                        )

        # --------------------------------------------------------
        # targets
        # --------------------------------------------------------

        targets = lookup.get(
            "targets"
        )

        if not isinstance(
            targets,
            dict
        ):

            errors.append(
                f"{location}.targets "
                f"must be an object"
            )

        else:

            for target_name, target in (
                targets.items()
            ):

                if not isinstance(
                    target,
                    dict
                ):

                    errors.append(
                        f"{location}.targets."
                        f"{target_name} "
                        f"must be an object"
                    )

                    continue

                enabled = target.get(
                    "enabled"
                )

                if not isinstance(
                    enabled,
                    bool
                ):

                    errors.append(
                        f"{location}.targets."
                        f"{target_name}.enabled "
                        f"must be boolean"
                    )

                if enabled and not target.get(
                    "lookup_name"
                ):

                    errors.append(
                        f"{location}.targets."
                        f"{target_name}.lookup_name "
                        f"is required when target "
                        f"is enabled"
                    )

    return errors


# ================================================================
# Validate schema
# ================================================================

def validate_schema(
    schema
):

    errors = []

    if "lookups" not in schema:

        errors.append(
            "schema.yaml must contain 'lookups'"
        )

        return errors

    if not isinstance(
        schema["lookups"],
        list
    ):

        errors.append(
            "schema.lookups must be a list"
        )

        return errors

    seen_ids = set()

    for index, lookup in enumerate(
        schema["lookups"]
    ):

        location = (
            f"schema.lookups[{index}]"
        )

        if not isinstance(
            lookup,
            dict
        ):

            errors.append(
                f"{location} must be an object"
            )

            continue

        lookup_id = lookup.get(
            "lookup_id"
        )

        if not lookup_id:

            errors.append(
                f"{location}.lookup_id is required"
            )

            continue

        if lookup_id in seen_ids:

            errors.append(
                f"Duplicate schema lookup_id: "
                f"{lookup_id}"
            )

        seen_ids.add(
            lookup_id
        )

        if not lookup.get(
            "name"
        ):

            errors.append(
                f"{location}.name is required"
            )

        if not lookup.get(
            "key"
        ):

            errors.append(
                f"{location}.key is required"
            )

        # --------------------------------------------------------
        # Common fields
        # --------------------------------------------------------

        common_fields = lookup.get(
            "common_fields"
        )

        if not isinstance(
            common_fields,
            dict
        ):

            errors.append(
                f"{location}.common_fields "
                f"must be an object"
            )

        else:

            for field_name, definition in (
                common_fields.items()
            ):

                field_location = (
                    f"{location}"
                    f".common_fields."
                    f"{field_name}"
                )

                if not isinstance(
                    definition,
                    dict
                ):

                    errors.append(
                        f"{field_location} "
                        f"must be an object"
                    )

                    continue

                field_type = definition.get(
                    "type"
                )

                if field_type not in (
                    "string",
                    "integer",
                    "date"
                ):

                    errors.append(
                        f"{field_location}.type "
                        f"must be string, integer "
                        f"or date"
                    )

                required = definition.get(
                    "required"
                )

                if not isinstance(
                    required,
                    bool
                ):

                    errors.append(
                        f"{field_location}.required "
                        f"must be boolean"
                    )

        # --------------------------------------------------------
        # SIEM-specific fields
        # --------------------------------------------------------

        siem_fields = lookup.get(
            "siem_specific_fields",
            {}
        )

        if not isinstance(
            siem_fields,
            dict
        ):

            errors.append(
                f"{location}.siem_specific_fields "
                f"must be an object"
            )

        else:

            for siem_name, fields in (
                siem_fields.items()
            ):

                if not isinstance(
                    fields,
                    dict
                ):

                    errors.append(
                        f"{location}."
                        f"siem_specific_fields."
                        f"{siem_name} must be an object"
                    )

                    continue

                for field_name, definition in (
                    fields.items()
                ):

                    field_location = (
                        f"{location}."
                        f"siem_specific_fields."
                        f"{siem_name}."
                        f"{field_name}"
                    )

                    if not isinstance(
                        definition,
                        dict
                    ):

                        errors.append(
                            f"{field_location} "
                            f"must be an object"
                        )

                        continue

                    if definition.get(
                        "type"
                    ) not in (
                        "string",
                        "integer",
                        "date"
                    ):

                        errors.append(
                            f"{field_location}.type "
                            f"is invalid"
                        )

                    required = definition.get(
                        "required"
                    )

                    if required is not None and not isinstance(
                        required,
                        bool
                    ):

                        errors.append(
                            f"{field_location}.required "
                            f"must be boolean"
                        )

    return errors


# ================================================================
# Load schema by lookup ID
# ================================================================

def load_schema_by_id(
    schema
):

    result = {}

    for lookup in schema.get(
        "lookups",
        []
    ):

        lookup_id = lookup.get(
            "lookup_id"
        )

        if lookup_id:

            result[
                lookup_id
            ] = lookup

    return result


# ================================================================
# Canonical field helpers
# ================================================================

def get_canonical_field_definitions(
    schema
):
    """
    Convert schema fields into the canonical
    flattened representation.

    Example:

        common_fields:
          indicator:

        siem_specific_fields:
          splunk:
            owner:

    becomes:

        indicator
        splunk_owner
    """

    definitions = {}

    # ------------------------------------------------------------
    # Common fields
    # ------------------------------------------------------------

    for field_name, definition in (
        schema.get(
            "common_fields",
            {}
        ).items()
    ):

        definitions[
            field_name
        ] = definition

    # ------------------------------------------------------------
    # SIEM-specific fields
    # ------------------------------------------------------------

    for siem, siem_fields in (
        schema.get(
            "siem_specific_fields",
            {}
        ).items()
    ):

        if not isinstance(
            siem_fields,
            dict
        ):
            continue

        for field_name, definition in (
            siem_fields.items()
        ):

            canonical_name = (
                f"{siem}_{field_name}"
            )

            definitions[
                canonical_name
            ] = definition

    return definitions


def get_canonical_fields(
    schema
):

    return list(
        get_canonical_field_definitions(
            schema
        ).keys()
    )


# ================================================================
# Validate mappings
# ================================================================

def load_and_validate_mappings(
    affected_ids,
    metadata_by_id,
    schema_by_id
):

    all_mappings = {}

    errors = []

    if not MAPPING_DIR.exists():

        errors.append(
            "mapping/ directory not found"
        )

        return all_mappings, errors

    mapping_files = sorted(
        MAPPING_DIR.glob("*.yaml")
    )

    if not mapping_files:

        errors.append(
            "No YAML files found in mapping/"
        )

        return all_mappings, errors

    for path in mapping_files:

        try:

            data = load_yaml(
                path
            )

        except ValidationError as exc:

            errors.append(
                str(exc)
            )

            continue

        mappings = data.get(
            "mappings"
        )

        if not isinstance(
            mappings,
            list
        ):

            errors.append(
                f"{path}: 'mappings' must be a list"
            )

            continue

        for index, mapping in enumerate(
            mappings
        ):

            location = (
                f"{path}:"
                f"mappings[{index}]"
            )

            if not isinstance(
                mapping,
                dict
            ):

                errors.append(
                    f"{location} must be an object"
                )

                continue

            lookup_id = mapping.get(
                "lookup_id"
            )

            name = mapping.get(
                "name"
            )

            siem = mapping.get(
                "siem"
            )

            fields = mapping.get(
                "fields"
            )

            defaults = mapping.get(
                "defaults",
                {}
            )

            # ----------------------------------------------------
            # Required properties
            # ----------------------------------------------------

            if not lookup_id:

                errors.append(
                    f"{location}.lookup_id is required"
                )

                continue

            if lookup_id not in metadata_by_id:

                errors.append(
                    f"{location}: "
                    f"{lookup_id} does not exist "
                    f"in metadata"
                )

            if lookup_id not in schema_by_id:

                errors.append(
                    f"{location}: "
                    f"{lookup_id} does not exist "
                    f"in schema"
                )

            if not name:

                errors.append(
                    f"{location}.name is required"
                )

            elif (
                lookup_id in metadata_by_id
                and
                name
                !=
                metadata_by_id[
                    lookup_id
                ].get("name")
            ):

                errors.append(
                    f"{location}: mapping name "
                    f"'{name}' does not match "
                    f"metadata name "
                    f"'{metadata_by_id[lookup_id].get('name')}'"
                )

            if not siem:

                errors.append(
                    f"{location}.siem is required"
                )

            if not isinstance(
                fields,
                dict
            ):

                errors.append(
                    f"{location}.fields "
                    f"must be an object"
                )

                continue

            if not isinstance(
                defaults,
                dict
            ):

                errors.append(
                    f"{location}.defaults "
                    f"must be an object"
                )

                defaults = {}

            # ----------------------------------------------------
            # Validate fields against FLATTENED canonical schema
            # ----------------------------------------------------

            if lookup_id in schema_by_id:

                schema_entry = (
                    schema_by_id[
                        lookup_id
                    ]
                )

                canonical_definitions = (
                    get_canonical_field_definitions(
                        schema_entry
                    )
                )

                allowed_fields = set(
                    canonical_definitions.keys()
                )

                # ------------------------------------------------
                # Validate mapping SIEM exists in schema
                # ------------------------------------------------

                siem_fields = schema_entry.get(
                    "siem_specific_fields",
                    {}
                )

                if siem not in siem_fields:

                    errors.append(
                        f"{location}: SIEM "
                        f"'{siem}' is not defined "
                        f"in schema for "
                        f"{lookup_id}"
                    )

                # ------------------------------------------------
                # Validate target -> canonical mappings
                # ------------------------------------------------

                for source_field, target_field in (
                    fields.items()
                ):

                    if not isinstance(
                        target_field,
                        str
                    ):

                        errors.append(
                            f"{location}: "
                            f"canonical mapping for "
                            f"'{source_field}' "
                            f"must be string"
                        )

                        continue

                    # IMPORTANT:
                    #
                    # Do NOT split on "." anymore.
                    #
                    # splunk_owner is a canonical field.
                    # splunk.owner is not accepted.
                    #

                    if target_field not in (
                        allowed_fields
                    ):

                        errors.append(
                            f"{location}: "
                            f"target field "
                            f"'{target_field}' "
                            f"is not defined "
                            f"in schema for "
                            f"{lookup_id}"
                        )

                # ------------------------------------------------
                # Validate defaults
                # ------------------------------------------------

                for field_name in defaults:

                    if field_name not in (
                        allowed_fields
                    ):

                        errors.append(
                            f"{location}: "
                            f"default field "
                            f"'{field_name}' "
                            f"is not defined "
                            f"in schema for "
                            f"{lookup_id}"
                        )

            all_mappings.setdefault(
                lookup_id,
                []
            ).append(
                {
                    "file": str(path),
                    "mapping": mapping,
                }
            )

    # ------------------------------------------------------------
    # Ensure affected canonical lookups have mappings
    # ------------------------------------------------------------

    for lookup_id in affected_ids:

        metadata = metadata_by_id[
            lookup_id
        ]

        canonical = metadata.get(
            "canonical",
            {}
        )

        if not canonical.get(
            "enabled",
            False
        ):

            continue

        if not all_mappings.get(
            lookup_id
        ):

            errors.append(
                f"{lookup_id}: no mapping found"
            )

    return all_mappings, errors


# ================================================================
# CSV
# ================================================================

def read_csv(
    path
):

    if not path.exists():

        raise ValidationError(
            f"CSV file not found: {path}"
        )

    if path.suffix.lower() != ".csv":

        raise ValidationError(
            f"Source file must be CSV: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(
            file
        )

        if reader.fieldnames is None:

            raise ValidationError(
                f"{path}: CSV has no header"
            )

        headers = [
            header.strip()
            for header in reader.fieldnames
        ]

        if len(headers) != len(
            set(headers)
        ):

            raise ValidationError(
                f"{path}: duplicate CSV columns"
            )

        rows = []

        for line_number, row in enumerate(
            reader,
            start=2
        ):

            cleaned = {}

            for key, value in row.items():

                clean_key = (
                    key.strip()
                )

                cleaned[
                    clean_key
                ] = (
                    value.strip()
                    if isinstance(
                        value,
                        str
                    )
                    else value
                )

            cleaned[
                "__line__"
            ] = line_number

            rows.append(
                cleaned
            )

        return headers, rows


# ================================================================
# Resolve source field
# ================================================================

def resolve_value(
    source_row,
    source_field
):

    if source_field not in source_row:

        raise ValidationError(
            f"Source column "
            f"'{source_field}' "
            f"not found in CSV"
        )

    return source_row.get(
        source_field,
        ""
    )


# ================================================================
# Build canonical row
# ================================================================

def build_canonical_row(
    source_row,
    mapping
):

    mapping_data = mapping.get(
        "mapping",
        mapping
    )

    field_mapping = mapping_data.get(
        "fields",
        {}
    )

    defaults = mapping_data.get(
        "defaults",
        {}
    )

    row = {}

    # ------------------------------------------------------------
    # Source -> Canonical
    #
    # Example:
    #
    # owner: splunk_owner
    #
    # means:
    #
    # CSV owner column
    #        |
    #        v
    # canonical splunk_owner
    # ------------------------------------------------------------

    for source_field, target_field in (
        field_mapping.items()
    ):

        if not isinstance(
            target_field,
            str
        ):

            raise ValidationError(
                f"Mapping target for "
                f"'{source_field}' must be string"
            )

        value = resolve_value(
            source_row,
            source_field
        )

        row[
            target_field
        ] = value

    # ------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------

    for field_name, default_value in (
        defaults.items()
    ):

        if (
            field_name not in row
            or
            row[field_name] == ""
            or
            row[field_name] is None
        ):

            row[
                field_name
            ] = str(
                default_value
            )

    return row


# ================================================================
# Validate canonical row
# ================================================================

def validate_canonical_row(
    row,
    schema,
    location
):

    canonical_definitions = (
        get_canonical_field_definitions(
            schema
        )
    )

    # ------------------------------------------------------------
    # Validate every canonical field that exists in row
    # ------------------------------------------------------------

    for field_name, value in row.items():

        if field_name not in (
            canonical_definitions
        ):

            raise ValidationError(
                f"{location}: field "
                f"'{field_name}' is not defined "
                f"in canonical schema"
            )

        definition = (
            canonical_definitions[
                field_name
            ]
        )

        required = definition.get(
            "required",
            False
        )

        if required and (
            value is None
            or
            str(value).strip() == ""
        ):

            raise ValidationError(
                f"{location}: required "
                f"field '{field_name}' "
                f"is empty"
            )

        validate_value_type(
            value,
            field_name,
            definition,
            location
        )

    # ------------------------------------------------------------
    # Validate required canonical fields
    # ------------------------------------------------------------

    for field_name, definition in (
        canonical_definitions.items()
    ):

        value = row.get(
            field_name,
            ""
        )

        required = definition.get(
            "required",
            False
        )

        if required and (
            value is None
            or
            str(value).strip() == ""
        ):

            raise ValidationError(
                f"{location}: required "
                f"field '{field_name}' "
                f"is missing or empty"
            )

        validate_value_type(
            value,
            field_name,
            definition,
            location
        )


# ================================================================
# Conflict detection
# ================================================================

def detect_conflict(
    canonical_row,
    schema,
    lookup_id,
    source_path,
    source_line,
    conflict_store
):

    canonical_key = schema.get(
        "key"
    )

    if not canonical_key:

        raise ValidationError(
            f"{lookup_id}: schema key "
            f"is missing"
        )

    key_value = canonical_row.get(
        canonical_key,
        ""
    )

    if (
        key_value is None
        or
        str(key_value).strip() == ""
    ):

        return

    key = (
        lookup_id,
        str(key_value).strip()
    )

    if key not in conflict_store:

        conflict_store[key] = {}

    # ------------------------------------------------------------
    # Only compare fields defined in canonical schema
    # ------------------------------------------------------------

    canonical_fields = (
        get_canonical_fields(
            schema
        )
    )

    for field in canonical_fields:

        if field == canonical_key:
            continue

        value = canonical_row.get(
            field,
            ""
        )

        if value in (
            None,
            ""
        ):

            continue

        value = str(
            value
        ).strip()

        previous = conflict_store[
            key
        ].get(
            field
        )

        if previous is None:

            conflict_store[
                key
            ][field] = (
                value,
                str(source_path),
                source_line
            )

            continue

        (
            previous_value,
            previous_path,
            previous_line
        ) = previous

        if value != previous_value:

            raise ConflictError(
                "\n"
                "======================================\n"
                "CANONICAL FIELD CONFLICT\n"
                "======================================\n"
                f"Lookup ID : {lookup_id}\n"
                f"Key field : {canonical_key}\n"
                f"Key value : {key_value}\n"
                f"Field     : {field}\n"
                "\n"
                "Existing value:\n"
                f"  Value : {previous_value}\n"
                f"  File  : {previous_path}\n"
                f"  Line  : {previous_line}\n"
                "\n"
                "New value:\n"
                f"  Value : {value}\n"
                f"  File  : {source_path}\n"
                f"  Line  : {source_line}\n"
                "\n"
                "Cannot create canonical lookup.\n"
                "======================================"
            )


# ================================================================
# Write canonical CSV
# ================================================================

def write_canonical(
    lookup_name,
    schema,
    rows
):

    LOOKUP_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        LOOKUP_DIR
        /
        f"{lookup_name}.csv"
    )

    # IMPORTANT:
    #
    # Common fields + flattened SIEM fields
    #

    fields = get_canonical_fields(
        schema
    )

    with open(
        output_file,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for row in rows:

            writer.writerow(
                {
                    field: row.get(
                        field,
                        ""
                    )
                    for field in fields
                }
            )

    return output_file



def read_existing_canonical(path, schema, lookup_id):
    if not path.exists():
        return [], False
    headers, rows = read_csv(path)
    expected = get_canonical_fields(schema)
    if headers != expected:
        raise ValidationError(
            f"{path}: canonical headers do not match schema. "
            f"Expected {expected}, got {headers}"
        )
    key_field = schema.get("key")
    seen = set()
    result = []
    for line, row in enumerate(rows, start=2):
        row = {k: row.get(k, "") for k in expected}
        validate_canonical_row(row, schema, f"{path}:{line}")
        key = str(row.get(key_field, "")).strip()
        if not key:
            raise ValidationError(f"{path}:{line}: canonical key '{key_field}' is empty")
        if key in seen:
            raise ValidationError(f"{path}:{line}: duplicate canonical key '{key}' value '{key}'")
        seen.add(key)
        result.append(row)
    return result, True


def merge_with_existing_canonical(lookup_id, output_file, schema, incoming_rows):
    existing_rows, exists = read_existing_canonical(output_file, schema, lookup_id)
    if not exists:
        return incoming_rows

    key_field = schema.get("key")
    fields = get_canonical_fields(schema)
    existing_by_key = {str(r[key_field]).strip(): dict(r) for r in existing_rows}

    for incoming in incoming_rows:
        key = str(incoming.get(key_field, "")).strip()
        if not key:
            raise ValidationError(f"{lookup_id}: incoming canonical key '{key_field}' is empty")

        if key not in existing_by_key:
            existing_by_key[key] = {f: incoming.get(f, "") for f in fields}
            continue

        existing = existing_by_key[key]
        for field in fields:
            new_value = incoming.get(field, "")
            old_value = existing.get(field, "")
            old_blank = old_value is None or str(old_value).strip() == ""
            new_blank = new_value is None or str(new_value).strip() == ""
            if old_blank and not new_blank:
                existing[field] = new_value
            elif not old_blank and not new_blank and str(old_value).strip() != str(new_value).strip():
                raise ConflictError(
                    "\n"
                    "======================================\n"
                    "CANONICAL FIELD CONFLICT\n"
                    "======================================\n"
                    f"Lookup ID : {lookup_id}\n"
                    f"Key field : {key_field}\n"
                    f"Key value : {key}\n"
                    f"Field     : {field}\n"
                    f"Existing value: {old_value}\n"
                    f"New value     : {new_value}\n"
                    "Existing canonical value is authoritative; no overwrite performed.\n"
                    "======================================"
                )

    return list(existing_by_key.values())


def record_processed_input(path):
    normalized = str(path).replace("\\", "/")
    existing = []
    if PROCESSED_MANIFEST.exists():
        existing = [x.strip() for x in PROCESSED_MANIFEST.read_text(encoding="utf-8").splitlines() if x.strip()]
    if normalized not in existing:
        existing.append(normalized)
    PROCESSED_MANIFEST.write_text("\n".join(existing) + "\n", encoding="utf-8")

# ================================================================
# Main
# ================================================================

def main():

    print(
        "======================================"
    )

    print(
        "Canonical Lookup Validation"
    )

    print(
        "======================================"
    )

    affected_ids = (
        get_affected_lookup_ids()
    )

    if not affected_ids:

        print(
            "No affected lookup IDs."
        )

        return

    print(
        f"Affected Lookup IDs: "
        f"{', '.join(affected_ids)}"
    )

    # ============================================================
    # Load files
    # ============================================================

    metadata = load_yaml(
        METADATA_FILE
    )

    schema = load_yaml(
        SCHEMA_FILE
    )

    # ============================================================
    # Validate metadata
    # ============================================================

    print("")
    print(
        "Validating metadata..."
    )

    metadata_errors = (
        validate_metadata(
            metadata
        )
    )

    # ============================================================
    # Validate schema
    # ============================================================

    print(
        "Validating schema..."
    )

    schema_errors = (
        validate_schema(
            schema
        )
    )

    # ============================================================
    # Structural errors
    # ============================================================

    structural_errors = (
        metadata_errors
        +
        schema_errors
    )

    if structural_errors:

        print("")
        print(
            "======================================"
        )

        print(
            "VALIDATION FAILED"
        )

        print(
            "======================================"
        )

        for error in structural_errors:

            print(
                f"ERROR: {error}"
            )

        sys.exit(1)

    # ============================================================
    # Index metadata/schema
    # ============================================================

    metadata_by_id = {
        lookup.get(
            "lookup_id"
        ): lookup
        for lookup in metadata.get(
            "lookups",
            []
        )
    }

    schema_by_id = (
        load_schema_by_id(
            schema
        )
    )

    # ============================================================
    # Validate affected IDs
    # ============================================================

    errors = []

    for lookup_id in affected_ids:

        if lookup_id not in metadata_by_id:

            errors.append(
                f"{lookup_id}: missing from metadata"
            )

        if lookup_id not in schema_by_id:

            errors.append(
                f"{lookup_id}: missing from schema"
            )

    if errors:

        print("")
        print(
            "======================================"
        )

        print(
            "VALIDATION FAILED"
        )

        print(
            "======================================"
        )

        for error in errors:

            print(
                f"ERROR: {error}"
            )

        sys.exit(1)

    # ============================================================
    # Validate mappings
    # ============================================================

    print(
        "Validating mappings..."
    )

    mappings, mapping_errors = (
        load_and_validate_mappings(
            affected_ids,
            metadata_by_id,
            schema_by_id
        )
    )

    if mapping_errors:

        print("")
        print(
            "======================================"
        )

        print(
            "MAPPING VALIDATION FAILED"
        )

        print(
            "======================================"
        )

        for error in mapping_errors:

            print(
                f"ERROR: {error}"
            )

        sys.exit(1)

    # ============================================================
    # Generate affected lookups
    # ============================================================

    for lookup_id in affected_ids:

        metadata_entry = (
            metadata_by_id[
                lookup_id
            ]
        )

        schema_entry = (
            schema_by_id[
                lookup_id
            ]
        )

        lookup_name = (
            metadata_entry[
                "name"
            ]
        )

        canonical = (
            metadata_entry.get(
                "canonical",
                {}
            )
        )

        if not canonical.get(
            "enabled",
            False
        ):

            print("")
            print(
                f"{lookup_id}: "
                f"canonical disabled - skipped"
            )

            continue

        print("")
        print(
            "======================================"
        )

        print(
            f"Generating {lookup_id}"
        )

        print(
            f"Name: {lookup_name}"
        )

        print(
            "======================================"
        )

        # --------------------------------------------------------
        # Reset conflict store for each lookup
        # --------------------------------------------------------

        conflict_store = {}

        canonical_rows = []

        # --------------------------------------------------------
        # Get source definitions
        # --------------------------------------------------------

        sources = metadata_entry.get(
            "sources",
            {}
        )

        if not isinstance(
            sources,
            dict
        ):

            raise ValidationError(
                f"{lookup_id}: sources "
                f"must be an object"
            )

        # --------------------------------------------------------
        # Process sources
        # --------------------------------------------------------

        for source_name, source in (
            sources.items()
        ):

            if not isinstance(
                source,
                dict
            ):

                continue

            source_file = source.get(
                "file"
            )

            if not source_file:

                continue

            source_path = Path(
                source_file
            )

            # ----------------------------------------------------
            # Find matching mapping
            # ----------------------------------------------------

            source_mapping = None

            for item in mappings.get(
                lookup_id,
                []
            ):

                mapping = item[
                    "mapping"
                ]

                if mapping.get(
                    "siem"
                ) == source_name:

                    source_mapping = mapping

                    break

            if source_mapping is None:

                raise ValidationError(
                    f"{lookup_id}: source "
                    f"'{source_name}' has file "
                    f"'{source_file}' but no "
                    f"matching mapping"
                )

            # ----------------------------------------------------
            # Read CSV
            # ----------------------------------------------------

            headers, source_rows = (
                read_csv(
                    source_path
                )
            )

            print(
                f"Source: {source_path}"
            )

            print(
                f"Rows: {len(source_rows)}"
            )

            # ----------------------------------------------------
            # Validate source fields
            # ----------------------------------------------------

            field_mapping = (
                source_mapping.get(
                    "fields",
                    {}
                )
            )

            for source_field in (
                field_mapping.keys()
            ):

                if source_field not in headers:

                    raise ValidationError(
                        f"{source_path}: "
                        f"source field "
                        f"'{source_field}' "
                        f"required by mapping "
                        f"for {lookup_id} "
                        f"is missing from CSV"
                    )

            # ----------------------------------------------------
            # Convert source rows
            # ----------------------------------------------------

            for source_row in source_rows:

                line_number = source_row.get(
                    "__line__"
                )

                canonical_row = (
                    build_canonical_row(
                        source_row,
                        source_mapping
                    )
                )

                location = (
                    f"{source_path}:"
                    f"{line_number}"
                )

                # ------------------------------------------------
                # Validate canonical fields
                # ------------------------------------------------

                validate_canonical_row(
                    canonical_row,
                    schema_entry,
                    location
                )

                # ------------------------------------------------
                # Detect conflicts
                # ------------------------------------------------

                detect_conflict(
                    canonical_row,
                    schema_entry,
                    lookup_id,
                    source_path,
                    line_number,
                    conflict_store
                )

                canonical_rows.append(
                    canonical_row
                )

        # --------------------------------------------------------
        # Remove duplicate canonical records
        # using canonical key
        # --------------------------------------------------------

        unique_rows = []

        seen_keys = set()

        canonical_key = schema_entry.get(
            "key"
        )

        for row in canonical_rows:

            key_value = row.get(
                canonical_key,
                ""
            )

            row_key = (
                str(key_value).strip()
            )

            if row_key in seen_keys:

                continue

            seen_keys.add(
                row_key
            )

            unique_rows.append(
                row
            )

        # --------------------------------------------------------
        # Validate final canonical dataset
        # --------------------------------------------------------

        for index, row in enumerate(
            unique_rows,
            start=2
        ):

            validate_canonical_row(
                row,
                schema_entry,
                f"canonical/{lookup_id}:"
                f"{index}"
            )

        # --------------------------------------------------------
        # Merge with existing canonical. Existing non-blank values
        # are authoritative; conflicting non-blank values fail.
        # --------------------------------------------------------

        output_file = LOOKUP_DIR / f"{lookup_name}.csv"
        merged_rows = merge_with_existing_canonical(
            lookup_id,
            output_file,
            schema_entry,
            unique_rows,
        )

        output_file = write_canonical(
            lookup_name,
            schema_entry,
            merged_rows
        )

        # Record only after this input source has been successfully
        # processed. The workflow archives these exact files only
        # after all target generation succeeds.
        record_processed_input(source_path)

        print(
            f"Generated: {output_file}"
        )

        print(
            f"Canonical fields: "
            f"{', '.join(get_canonical_fields(schema_entry))}"
        )

        print(
            f"Canonical rows: "
            f"{len(unique_rows)}"
        )

    # ============================================================
    # Complete
    # ============================================================

    print("")
    print(
        "======================================"
    )

    print(
        "VALIDATION PASSED"
    )

    print(
        "Canonical lookup generation complete"
    )

    print(
        "======================================"
    )


# ================================================================
# Entry point
# ================================================================

if __name__ == "__main__":

    try:

        main()

    except (
        ValidationError,
        ConflictError
    ) as exc:

        print("")
        print(
            "======================================"
        )

        print(
            "ERROR"
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
